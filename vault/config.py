"""Configuration and logging utilities for the secure vault.

This module centralizes security policy configuration, logging setup, and
audit trail helpers. It supports dependency injection for the core vault
engine and UIs.

Architecture Overview:
- SecurityPolicy defines configurable KDF parameters and app behavior.
- Config storage uses JSON at `vault/storage/config.json` with safe defaults.
- Logging emits to `vault/storage/audit.log` with restrictive permissions.

Threat Model Notes:
- Audit logs must not include secrets. Only metadata and event categories
  are recorded. Files are created with `0o600` permissions on POSIX.
- Config values are treated as non-sensitive; secrets (master password,
  keys) are never logged or stored.

Google-Style Docstrings are used for clarity and maintainability.
"""

from __future__ import annotations

import json
import logging
import os
import base64
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Dict, Optional


DEFAULT_CONFIG_PATH = os.path.join(os.path.dirname(__file__), "storage", "config.json")
DEFAULT_VAULT_PATH = os.path.join(os.path.dirname(__file__), "storage", "vault.json")
DEFAULT_AUDIT_LOG_PATH = os.path.join(os.path.dirname(__file__), "storage", "audit.log")
DEFAULT_INSTANCE_SECRET_PATH = os.path.join(os.path.dirname(__file__), "storage", "instance.secret")


@dataclass
class SecurityPolicy:
    """Security policy configuration.

    Attributes:
        pbkdf2_iterations: Number of PBKDF2-HMAC-SHA256 iterations.
        min_master_length: Minimum length for master password.
        auto_sync_enabled: Whether cloud sync is enabled automatically.
        proton_drive_path: Target path for encrypted vault sync (local folder).
        biometric_enabled: Whether biometric unlock is enabled.
        biometric_storage_path: Path to SQLite DB storing encrypted master blob.
    """

    pbkdf2_iterations: int = 200_000
    min_master_length: int = 12
    auto_sync_enabled: bool = False
    proton_drive_path: str = ""
    biometric_enabled: bool = False
    biometric_storage_path: str = os.path.join(
        os.path.dirname(__file__), "storage", "biometric.db"
    )


def load_config(path: str = DEFAULT_CONFIG_PATH) -> Dict[str, Any]:
    """Load configuration JSON.

    Args:
        path: Path to the configuration file.

    Returns:
        A dictionary with configuration values. If the file does not exist,
        a default configuration is created and written atomically.

    Raises:
        json.JSONDecodeError: If the config file contains invalid JSON.
    """

    default = {
        "version": "1.0.0",
        "pbkdf2_iterations": 200000,
        "proton_drive_path": "",
        "biometric_enabled": False,
        "biometric_storage_path": os.path.join(
            os.path.dirname(__file__), "storage", "biometric.db"
        ),
        "auto_sync_enabled": False,
        "created_at": datetime.utcnow().isoformat(),
        "last_backup": None,
        # Auth and security additions
        "master_password_hash": None,
        "master_set_count": 0,
        "last_master_set_at": None,
        "rotations_count": 0,
        "last_rotation_at": None,
        "app_instance_id": None,
        "app_salt_b64": None,
        "csrf_secret_b64": None,
        "enforce_https": False,
        "rate_limit_window_sec": 60,
        "rate_limit_max": 5,
        "bcrypt_rounds": 14,
    }

    if not os.path.exists(path):
        _atomic_write_json(path, default)
        return default

    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def _atomic_write_json(path: str, data: Dict[str, Any]) -> None:
    """Write JSON atomically to disk.

    Args:
        path: Target JSON path.
        data: Serializable data.

    Notes:
        Uses a temp file and `os.replace` for atomic write semantics.
    """

    directory = os.path.dirname(path)
    os.makedirs(directory, exist_ok=True)
    tmp_path = f"{path}.tmp"
    with open(tmp_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp_path, path)


def configure_logging(audit_path: str = DEFAULT_AUDIT_LOG_PATH) -> logging.Logger:
    """Configure secure logging to an audit trail file.

    Args:
        audit_path: Path to the audit log file.

    Returns:
        A configured `logging.Logger` instance.

    Security:
        - Creates the file if absent and restricts permissions to 0o600.
        - Avoids logging secrets; callers must pass sanitized metadata only.
    """

    logger = logging.getLogger("vault_audit")
    logger.setLevel(logging.INFO)

    # Avoid duplicate handlers if reconfigured
    if not logger.handlers:
        os.makedirs(os.path.dirname(audit_path), exist_ok=True)
        # Pre-create with restrictive permissions on POSIX
        if not os.path.exists(audit_path):
            with open(audit_path, "a", encoding="utf-8"):
                pass
            try:
                os.chmod(audit_path, 0o600)
            except Exception:
                # On non-POSIX, chmod may fail; proceed without raising.
                pass

        handler = logging.FileHandler(audit_path, encoding="utf-8")
        formatter = logging.Formatter(
            fmt="%(asctime)sZ %(levelname)s %(message)s",
            datefmt="%Y-%m-%dT%H:%M:%S",
        )
        handler.setFormatter(formatter)
        logger.addHandler(handler)

    return logger


def ensure_instance_materials(cfg_path: str = DEFAULT_CONFIG_PATH) -> Dict[str, Any]:
    """Ensure config contains instance-bound materials and on-disk secret.

    - Generates and persists `app_instance_id`, `app_salt_b64`, `csrf_secret_b64` if missing.
    - Creates an on-disk `instance.secret` file (0o600) containing a high-entropy secret.

    Returns:
        Updated config dict.
    """
    cfg = load_config(cfg_path)
    changed = False

    if not cfg.get("app_instance_id"):
        import uuid
        cfg["app_instance_id"] = str(uuid.uuid4())
        changed = True

    if not cfg.get("app_salt_b64"):
        app_salt = os.urandom(16)
        cfg["app_salt_b64"] = base64.urlsafe_b64encode(app_salt).decode("ascii")
        changed = True

    if not cfg.get("csrf_secret_b64"):
        csrf = os.urandom(32)
        cfg["csrf_secret_b64"] = base64.urlsafe_b64encode(csrf).decode("ascii")
        changed = True

    # Ensure instance secret file exists with restrictive permissions
    if not os.path.exists(DEFAULT_INSTANCE_SECRET_PATH):
        os.makedirs(os.path.dirname(DEFAULT_INSTANCE_SECRET_PATH), exist_ok=True)
        with open(DEFAULT_INSTANCE_SECRET_PATH, "wb") as f:
            f.write(os.urandom(32))
            f.flush()
            os.fsync(f.fileno())
        try:
            os.chmod(DEFAULT_INSTANCE_SECRET_PATH, 0o600)
        except Exception:
            pass

    if changed:
        _atomic_write_json(cfg_path, cfg)
    return cfg


def save_config(cfg: Dict[str, Any], path: str = DEFAULT_CONFIG_PATH) -> None:
    """Persist provided config dict atomically."""
    _atomic_write_json(path, cfg)


def get_instance_secret() -> bytes:
    """Read the instance secret bytes from disk, creating if missing."""
    ensure_instance_materials()
    with open(DEFAULT_INSTANCE_SECRET_PATH, "rb") as f:
        return f.read()


def get_app_salt() -> bytes:
    """Return application-specific salt bytes from config."""
    cfg = ensure_instance_materials()
    b64 = cfg.get("app_salt_b64") or ""
    import base64 as _b64
    return _b64.urlsafe_b64decode(b64.encode("ascii"))


def get_csrf_secret() -> str:
    """Return CSRF secret in base64 form from config."""
    cfg = ensure_instance_materials()
    return cfg.get("csrf_secret_b64") or ""


def get_master_password_hash() -> Optional[str]:
    """Return stored bcrypt hash for the master password (or None)."""
    cfg = load_config()
    return cfg.get("master_password_hash")


def set_master_password_hash(hash_str: str) -> None:
    """Store bcrypt hash string for the master password."""
    cfg = load_config()
    cfg["master_password_hash"] = hash_str
    save_config(cfg)


def clear_master_password_hash() -> None:
    """Clear stored bcrypt hash for the master password (set to None)."""
    cfg = load_config()
    cfg["master_password_hash"] = None
    save_config(cfg)


class AuditLogger:
    """Append-only audit logger emitting JSON lines.

    Records event categories and metadata without including secrets.

    Args:
        logger: The base `logging.Logger` configured for audit output.

    Methods:
        emit: Write a structured event.
    """

    def __init__(self, logger: Optional[logging.Logger] = None) -> None:
        self._logger = logger or configure_logging()

    def emit(self, category: str, metadata: Optional[Dict[str, Any]] = None) -> None:
        """Emit a structured audit event.

        Args:
            category: Event category (e.g., "add_entry", "get_entry").
            metadata: Non-sensitive metadata. Must exclude secrets.
        """
        meta = metadata or {}
        safe = {
            k: v
            for k, v in meta.items()
            if k not in {"username", "password", "master_password"}
        }
        payload = {
            "category": category,
            "metadata": safe,
            "ts": datetime.utcnow().isoformat() + "Z",
        }
        self._logger.info(json.dumps(payload, ensure_ascii=False))


def build_policy_from_config(cfg: Dict[str, Any]) -> SecurityPolicy:
    """Create a `SecurityPolicy` from raw config values.

    Args:
        cfg: Raw configuration dict.

    Returns:
        A `SecurityPolicy` with values populated from config or defaults.
    """
    return SecurityPolicy(
        pbkdf2_iterations=int(cfg.get("pbkdf2_iterations", 200000)),
        auto_sync_enabled=bool(cfg.get("auto_sync_enabled", False)),
        proton_drive_path=str(cfg.get("proton_drive_path", "")),
        biometric_enabled=bool(cfg.get("biometric_enabled", False)),
        biometric_storage_path=str(
            cfg.get(
                "biometric_storage_path",
                os.path.join(os.path.dirname(__file__), "storage", "biometric.db"),
            )
        ),
    )
