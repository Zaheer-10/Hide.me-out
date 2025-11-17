# pyright: reportMissingImports=false
# pyright: reportMissingTypeStubs=false
# mypy: ignore-missing-imports
"""Core encryption engine for the secure password vault.

Enterprise-Grade Architecture:
- Dependency injection for policy and audit components.
- Strict input validation and sanitization.
- Atomic file operations for durability.
- Configurable PBKDF2 iterations (default 200,000).
- Authenticated encryption with Fernet for each field.
- Service name obfuscation to reduce metadata leakage.

Threat Model Analysis:
- Offline attacker with vault.json: Cannot decrypt without master password;
  Fernet validation prevents silent tampering.
- Insider threats via logs: Secrets are never logged; audit trail records only
  categories and safe metadata.
- Weak master passwords: Enforce minimum length and recommend strong passphrases.

This module exposes simple functional APIs per requirements while internally
using a `VaultEngine` to maintain separation of concerns.
"""

from __future__ import annotations

import base64
import json
import os
import secrets
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Dict, List, Optional

from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC  # type: ignore
from cryptography.hazmat.primitives import hashes  # type: ignore
from cryptography.fernet import Fernet, InvalidToken  # type: ignore

from .config import (
    AuditLogger,
    DEFAULT_VAULT_PATH,
    SecurityPolicy,
    build_policy_from_config,
    load_config,
)
from .utils.obfuscation import (
    obfuscate_service_name,
    deobfuscate_service_name,
)
from .utils.cloud_sync import sync_encrypted_vault


@dataclass
class VaultEngine:
    """Core engine handling encryption, decryption, and storage.

    Args:
        policy: Configurable security policy.
        audit: Audit logger for non-sensitive event recording.
        vault_path: Path to encrypted vault JSON file.
    """

    policy: SecurityPolicy
    audit: Optional[AuditLogger]
    vault_path: str = DEFAULT_VAULT_PATH

    # ------------------------ Security Primitives -------------------------
    def derive_key(self, master_password: str, salt: bytes) -> bytes:
        """Derive a 32-byte key using PBKDF2-HMAC-SHA256.

        Args:
            master_password: Master password string.
            salt: 16-byte per-entry salt.

        Returns:
            32-byte derived key (raw bytes).
        """
        if not isinstance(salt, (bytes, bytearray)) or len(salt) != 16:
            raise ValueError("Salt must be 16 bytes")
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=self.policy.pbkdf2_iterations,
        )
        return kdf.derive(master_password.encode("utf-8"))

    def _fernet_from_key(self, derived_key: bytes) -> Fernet:
        """Create a Fernet instance from a raw 32-byte key.

        Args:
            derived_key: Raw 32-byte key.

        Returns:
            A `Fernet` cipher instance.
        """
        return Fernet(base64.urlsafe_b64encode(derived_key))

    # --------------------------- I/O Utilities ----------------------------
    def load_vault(self) -> Dict[str, Any]:
        """Load the encrypted vault JSON.

        Returns:
            A dictionary representing the vault contents.

        Notes:
            Returns an empty dict if the file does not exist.
        """
        try:
            if not os.path.exists(self.vault_path):
                return {}
            with open(self.vault_path, "r", encoding="utf-8") as f:
                return json.load(f)
        except json.JSONDecodeError:
            raise
        except Exception:
            # In production, consider raising a custom exception; for now return empty.
            return {}

    def save_vault(self, vault_data: Dict[str, Any]) -> bool:
        """Save the vault JSON atomically.

        Args:
            vault_data: The vault contents to persist.

        Returns:
            True on success, False otherwise.
        """
        try:
            directory = os.path.dirname(self.vault_path)
            os.makedirs(directory, exist_ok=True)
            tmp_path = f"{self.vault_path}.tmp"
            with open(tmp_path, "w", encoding="utf-8") as f:
                json.dump(vault_data, f, indent=2)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp_path, self.vault_path)
            return True
        except Exception:
            # Best-effort cleanup
            try:
                if os.path.exists(tmp_path):
                    os.remove(tmp_path)
            except Exception:
                pass
            return False

    # ----------------------------- Operations ----------------------------
    def add_entry(
        self,
        master_password: str,
        service_name: str,
        username: str,
        password: str,
        source_info: str = "",
    ) -> bool:
        """Add a new encrypted entry to the vault.

        Args:
            master_password: Master password for key derivation.
            service_name: Logical service identifier.
            username: Account username/email.
            password: Account password.
            source_info: Optional link or description.

        Returns:
            True if successful.
        """
        if len(master_password) < self.policy.min_master_length:
            raise ValueError("Master password too short")
        if not service_name or not username or not password:
            raise ValueError("service_name, username, and password are required")

        salt = secrets.token_bytes(16)
        key = self.derive_key(master_password, salt)
        cipher = self._fernet_from_key(key)

        enc_username = cipher.encrypt(username.encode("utf-8")).decode("ascii")
        enc_password = cipher.encrypt(password.encode("utf-8")).decode("ascii")
        enc_source = cipher.encrypt((source_info or "").encode("utf-8")).decode("ascii")

        obf_key = obfuscate_service_name(service_name, salt)

        vault = self.load_vault()
        now = datetime.utcnow().isoformat() + "Z"
        vault[obf_key] = {
            "username": enc_username,
            "password": enc_password,
            "source": enc_source,
            "salt": base64.urlsafe_b64encode(salt).decode("ascii"),
            "created_at": now,
            "updated_at": now,
        }
        ok = self.save_vault(vault)
        if ok and self.policy.auto_sync_enabled and self.policy.proton_drive_path:
            try:
                sync_encrypted_vault(self.vault_path, self.policy.proton_drive_path)
            except Exception:
                pass
        if ok and self.audit:
            self.audit.emit("add_entry", {"service_obf": obf_key})
        return ok

    def get_entry(self, master_password: str, service_name: str) -> Optional[Dict[str, str]]:
        """Retrieve and decrypt an entry by service name.

        Args:
            master_password: Master password.
            service_name: Service identifier.

        Returns:
            A dict with decrypted fields or None if not found.
        """
        vault = self.load_vault()
        for obf_key, entry in vault.items():
            try:
                salt = base64.urlsafe_b64decode(entry["salt"].encode("ascii"))
                name = deobfuscate_service_name(obf_key, salt)
                if name != service_name:
                    continue
                key = self.derive_key(master_password, salt)
                cipher = self._fernet_from_key(key)
                username = cipher.decrypt(entry["username"].encode("ascii")).decode("utf-8")
                password = cipher.decrypt(entry["password"].encode("ascii")).decode("utf-8")
                source = cipher.decrypt(entry["source"].encode("ascii")).decode("utf-8")
                if self.audit:
                    self.audit.emit("get_entry", {"service_obf": obf_key})
                return {
                    "service_name": name,
                    "username": username,
                    "password": password,
                    "source_info": source,
                }
            except (InvalidToken, KeyError, ValueError):
                # Invalid token indicates wrong master password or tampering.
                continue
        return None

    def search_entries(self, master_password: str, keyword: str) -> List[Dict[str, str]]:
        """Search entries for a keyword across decrypted fields.

        Args:
            master_password: Master password.
            keyword: Case-insensitive search term.

        Returns:
            A list of matching decrypted entry dicts.
        """
        keyword_lower = (keyword or "").lower()
        results: List[Dict[str, str]] = []
        vault = self.load_vault()
        for obf_key, entry in vault.items():
            try:
                salt = base64.urlsafe_b64decode(entry["salt"].encode("ascii"))
                name = deobfuscate_service_name(obf_key, salt)
                key = self.derive_key(master_password, salt)
                cipher = self._fernet_from_key(key)
                username = cipher.decrypt(entry["username"].encode("ascii")).decode("utf-8")
                password = cipher.decrypt(entry["password"].encode("ascii")).decode("utf-8")
                source = cipher.decrypt(entry["source"].encode("ascii")).decode("utf-8")

                haystack = " ".join([name, username, source]).lower()
                if keyword_lower in haystack:
                    results.append({
                        "service_name": name,
                        "username": username,
                        "password": password,
                        "source_info": source,
                    })
            except (InvalidToken, KeyError, ValueError):
                continue
        if self.audit:
            self.audit.emit("search_entries", {"count": len(results)})
        return results

    def update_entry(
        self,
        master_password: str,
        service_name: str,
        username: Optional[str] = None,
        password: Optional[str] = None,
        source_info: Optional[str] = None,
    ) -> bool:
        """Update an existing entry.

        Args:
            master_password: Master password.
            service_name: Service name to update.
            username: Optional new username.
            password: Optional new password.
            source_info: Optional new source info.

        Returns:
            True if updated successfully; False otherwise.
        """
        vault = self.load_vault()
        for obf_key, entry in vault.items():
            try:
                salt = base64.urlsafe_b64decode(entry["salt"].encode("ascii"))
                name = deobfuscate_service_name(obf_key, salt)
                if name != service_name:
                    continue

                # Re-encrypt with a fresh salt to avoid salt reuse
                new_salt = secrets.token_bytes(16)
                key = self.derive_key(master_password, new_salt)
                cipher = self._fernet_from_key(key)

                new_username = username if username is not None else self._decrypt_field(master_password, entry["username"], salt)
                new_password = password if password is not None else self._decrypt_field(master_password, entry["password"], salt)
                new_source = source_info if source_info is not None else self._decrypt_field(master_password, entry["source"], salt)

                enc_username = cipher.encrypt(new_username.encode("utf-8")).decode("ascii")
                enc_password = cipher.encrypt(new_password.encode("utf-8")).decode("ascii")
                enc_source = cipher.encrypt((new_source or "").encode("utf-8")).decode("ascii")

                new_obf_key = obfuscate_service_name(service_name, new_salt)
                now = datetime.utcnow().isoformat() + "Z"
                vault.pop(obf_key)
                vault[new_obf_key] = {
                    "username": enc_username,
                    "password": enc_password,
                    "source": enc_source,
                    "salt": base64.urlsafe_b64encode(new_salt).decode("ascii"),
                    "created_at": entry.get("created_at", now),
                    "updated_at": now,
                }
                ok = self.save_vault(vault)
                if ok and self.policy.auto_sync_enabled and self.policy.proton_drive_path:
                    try:
                        sync_encrypted_vault(self.vault_path, self.policy.proton_drive_path)
                    except Exception:
                        pass
                if ok and self.audit:
                    self.audit.emit("update_entry", {"service_obf": new_obf_key})
                return ok
            except Exception:
                continue
        return False

    def delete_entry(self, master_password: str, service_name: str) -> bool:
        """Delete an entry by service name.

        Args:
            master_password: Master password (unused here, but can verify auth flow).
            service_name: Service name.

        Returns:
            True if deleted; False otherwise.
        """
        vault = self.load_vault()
        for obf_key, entry in list(vault.items()):
            try:
                salt = base64.urlsafe_b64decode(entry["salt"].encode("ascii"))
                name = deobfuscate_service_name(obf_key, salt)
                if name == service_name:
                    vault.pop(obf_key)
                    ok = self.save_vault(vault)
                    if ok and self.policy.auto_sync_enabled and self.policy.proton_drive_path:
                        try:
                            sync_encrypted_vault(self.vault_path, self.policy.proton_drive_path)
                        except Exception:
                            pass
                    if ok and self.audit:
                        self.audit.emit("delete_entry", {"service_obf": obf_key})
                    return ok
            except Exception:
                continue
        return False

    # ----------------------------- Helpers --------------------------------
    def _decrypt_field(self, master_password: str, enc: str, salt: bytes) -> str:
        key = self.derive_key(master_password, salt)
        cipher = self._fernet_from_key(key)
        return cipher.decrypt(enc.encode("ascii")).decode("utf-8")

    # ---------------------- Master Rotation / Wipe -----------------------
    def rotate_master(self, old_master: str, new_master: str) -> int:
        """Re-encrypt all entries from old_master to new_master.

        Returns:
            Count of entries successfully re-encrypted.
        """
        if len(new_master) < self.policy.min_master_length:
            raise ValueError("New master password too short")
        vault = self.load_vault()
        updated: Dict[str, Any] = {}
        count = 0
        for obf_key, entry in vault.items():
            try:
                salt = base64.urlsafe_b64decode(entry["salt"].encode("ascii"))
                name = deobfuscate_service_name(obf_key, salt)
                # Decrypt with old master
                old_username = self._decrypt_field(old_master, entry["username"], salt)
                old_password = self._decrypt_field(old_master, entry["password"], salt)
                old_source = self._decrypt_field(old_master, entry["source"], salt)

                # Re-encrypt with new master and fresh salt
                new_salt = secrets.token_bytes(16)
                key = self.derive_key(new_master, new_salt)
                cipher = self._fernet_from_key(key)
                enc_username = cipher.encrypt(old_username.encode("utf-8")).decode("ascii")
                enc_password = cipher.encrypt(old_password.encode("utf-8")).decode("ascii")
                enc_source = cipher.encrypt((old_source or "").encode("utf-8")).decode("ascii")
                new_obf_key = obfuscate_service_name(name, new_salt)
                now = datetime.utcnow().isoformat() + "Z"
                updated[new_obf_key] = {
                    "username": enc_username,
                    "password": enc_password,
                    "source": enc_source,
                    "salt": base64.urlsafe_b64encode(new_salt).decode("ascii"),
                    "created_at": entry.get("created_at", now),
                    "updated_at": now,
                }
                count += 1
            except Exception:
                # Skip entries that cannot be decrypted with the old master
                continue
        if count:
            ok = self.save_vault(updated)
            if ok and self.policy.auto_sync_enabled and self.policy.proton_drive_path:
                try:
                    sync_encrypted_vault(self.vault_path, self.policy.proton_drive_path)
                except Exception:
                    pass
            if ok and self.audit:
                self.audit.emit("rotate_master", {"count": count})
        return count

    def wipe(self) -> bool:
        """Wipe all entries from the vault."""
        ok = True
        try:
            if os.path.exists(self.vault_path):
                os.remove(self.vault_path)
        except Exception:
            ok = self.save_vault({})
        if ok and self.audit:
            self.audit.emit("wipe_vault", {})
        return ok


# ---------------------------- Functional API ------------------------------
_cfg = load_config()
_policy = build_policy_from_config(_cfg)
_audit = AuditLogger()
_engine = VaultEngine(policy=_policy, audit=_audit)


def derive_key(master_password: str, salt: bytes, iterations: Optional[int] = None) -> bytes:
    """Module-level key derivation helper.

    Args:
        master_password: Master password.
        salt: 16-byte salt.
        iterations: Optional iteration override.

    Returns:
        Derived key bytes.
    """
    if iterations is not None:
        local_policy = SecurityPolicy(pbkdf2_iterations=iterations)
        local_engine = VaultEngine(policy=local_policy, audit=_audit)
        return local_engine.derive_key(master_password, salt)
    return _engine.derive_key(master_password, salt)


def add_entry(master: str, service: str, username: str, password: str, source_info: str = "") -> bool:
    """Add a vault entry (requirements API).

    Args:
        master: Master password.
        service: Service name.
        username: Username/email.
        password: Password.
        source_info: Optional source info (URL/text).

    Returns:
        True on success.
    """
    return _engine.add_entry(master, service, username, password, source_info)


def get_entry(master: str, service: str) -> Optional[Dict[str, str]]:
    """Get and decrypt a vault entry (requirements API)."""
    return _engine.get_entry(master, service)


def search_entries(master: str, keyword: str) -> List[Dict[str, str]]:
    """Search vault entries (requirements API)."""
    return _engine.search_entries(master, keyword)


def update_entry(master: str, service: str, username: Optional[str] = None, password: Optional[str] = None, source_info: Optional[str] = None) -> bool:
    """Update an existing vault entry (requirements API).

    Args:
        master: Master password.
        service: Service name to update.
        username: Optional new username.
        password: Optional new password.
        source_info: Optional new source info.

    Returns:
        True on success.
    """
    return _engine.update_entry(master, service, username=username, password=password, source_info=source_info)


def delete_entry(master: str, service: str) -> bool:
    """Delete a vault entry (requirements API)."""
    return _engine.delete_entry(master, service)


def rotate_master_password(old_master: str, new_master: str) -> int:
    """Rotate master password and re-encrypt all entries.

    Returns:
        Count of entries updated.
    """
    return _engine.rotate_master(old_master, new_master)


def wipe_vault() -> bool:
    """Wipe all entries from the vault."""
    return _engine.wipe()


def export_vault(path: str) -> bool:
    """Export vault to a JSON backup file in plaintext fields.

    WARNING: This exports decrypted entries to the provided path.
    Handle the resulting file securely and delete immediately after use.
    """
    try:
        # For export, require a master password via environment variable to avoid interactive API.
        master = os.environ.get("VAULT_MASTER_PASSWORD", "")
        if not master:
            raise ValueError("VAULT_MASTER_PASSWORD env var is required for export")
        vault = _engine.load_vault()
        out: List[Dict[str, str]] = []
        for obf_key, entry in vault.items():
            salt = base64.urlsafe_b64decode(entry["salt"].encode("ascii"))
            name = deobfuscate_service_name(obf_key, salt)
            key = _engine.derive_key(master, salt)
            cipher = _engine._fernet_from_key(key)
            out.append({
                "service_name": name,
                "username": cipher.decrypt(entry["username"].encode("ascii")).decode("utf-8"),
                "password": cipher.decrypt(entry["password"].encode("ascii")).decode("utf-8"),
                "source_info": cipher.decrypt(entry["source"].encode("ascii")).decode("utf-8"),
            })
        with open(path, "w", encoding="utf-8") as f:
            json.dump(out, f, indent=2)
        _audit.emit("export_vault", {"path": path, "count": len(out)})
        return True
    except Exception:
        return False


def import_vault(path: str, merge: bool = False) -> bool:
    """Import entries from a plaintext JSON backup file.

    WARNING: The input file is assumed to contain plaintext fields and must
    be handled securely. The master password is required in env var
    `VAULT_MASTER_PASSWORD`.
    """
    try:
        master = os.environ.get("VAULT_MASTER_PASSWORD", "")
        if not master:
            raise ValueError("VAULT_MASTER_PASSWORD env var is required for import")
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        if not isinstance(data, list):
            raise ValueError("Invalid import format; expected a list of entries")

        if not merge:
            # Reset vault
            _engine.save_vault({})

        count = 0
        for item in data:
            ok = _engine.add_entry(
                master,
                item.get("service_name", ""),
                item.get("username", ""),
                item.get("password", ""),
                item.get("source_info", ""),
            )
            count += int(bool(ok))
        _audit.emit("import_vault", {"path": path, "count": count, "merge": merge})
        return True
    except Exception:
        return False


# Convenience aliases required by spec
obfuscate = obfuscate_service_name
deobfuscate = deobfuscate_service_name
load_vault = _engine.load_vault
save_vault = _engine.save_vault


def count_entries() -> int:
    try:
        v = _engine.load_vault()
        return len(v)
    except Exception:
        return 0