"""S3 cloud storage utilities for the secure vault.

Provides S3 integration for vault synchronization with security best practices:
- Server-side encryption (SSE-S3)
- Encrypted master password hints
- Atomic download/upload operations
- Automatic retry with exponential backoff

Environment Variables:
- AWS_ACCESS_KEY_ID: AWS access key
- AWS_SECRET_ACCESS_KEY: AWS secret key
- S3_BUCKET_NAME: Target S3 bucket
- AWS_REGION: AWS region (default: ap-south-2)
- S3_VAULT_PATH: Path prefix in bucket (default: vault/)

Security Constraints:
- Never upload unencrypted sensitive data
- Hints are encrypted with app instance secret before storage
- All S3 objects use server-side encryption
"""

from __future__ import annotations

import base64
import json
import os
import tempfile
from datetime import datetime
from typing import Any, Dict, Optional, Tuple
from dotenv import load_dotenv

load_dotenv()

# Lazy import to avoid startup failures when boto3 is not installed
_s3_client = None


def _get_s3_config() -> Dict[str, str]:
    """Get S3 configuration from environment variables.

    Returns:
        Dict with S3 configuration:
        - access_key: AWS access key ID
        - secret_key: AWS secret access key
        - bucket: S3 bucket name
        - region: AWS region
        - vault_path: Path prefix for vault files in bucket
    """
    return {
        "access_key": os.environ.get("AWS_ACCESS_KEY_ID", ""),
        "secret_key": os.environ.get("AWS_SECRET_ACCESS_KEY", ""),
        "bucket": os.environ.get("S3_BUCKET_NAME", ""),
        "region": os.environ.get("AWS_REGION", "ap-south-2"),
        "vault_path": os.environ.get("S3_VAULT_PATH", "vault/"),
    }


def is_s3_configured() -> bool:
    """Check if S3 is properly configured.

    Returns:
        True if all required S3 env vars are set.
    """
    cfg = _get_s3_config()
    return bool(cfg["access_key"] and cfg["secret_key"] and cfg["bucket"])


def _get_s3_client():
    """Get or create the S3 client (lazy initialization).

    Returns:
        boto3 S3 client instance.

    Raises:
        ImportError: If boto3 is not installed.
        ValueError: If S3 is not configured.
    """
    global _s3_client
    if _s3_client is not None:
        return _s3_client

    try:
        import boto3  # type: ignore
        from botocore.config import Config  # type: ignore
    except ImportError:
        raise ImportError(
            "boto3 is required for S3 storage. " "Install with: pip install boto3"
        )

    cfg = _get_s3_config()
    if not is_s3_configured():
        raise ValueError(
            "S3 not configured. Set AWS_ACCESS_KEY_ID, "
            "AWS_SECRET_ACCESS_KEY, and S3_BUCKET_NAME environment variables."
        )

    # Configure with retries and timeouts
    boto_config = Config(
        region_name=cfg["region"],
        retries={
            "max_attempts": 3,
            "mode": "standard",
        },
        connect_timeout=10,
        read_timeout=30,
    )

    _s3_client = boto3.client(
        "s3",
        aws_access_key_id=cfg["access_key"],
        aws_secret_access_key=cfg["secret_key"],
        region_name=cfg["region"],
        config=boto_config,
    )
    return _s3_client


def _get_vault_s3_key() -> str:
    """Get the S3 key for the vault file.

    Returns:
        S3 object key for vault.json
    """
    cfg = _get_s3_config()
    path = cfg["vault_path"].rstrip("/")
    return f"{path}/vault.json"


def _get_config_s3_key() -> str:
    """Get the S3 key for the config file.

    Returns:
        S3 object key for config.json
    """
    cfg = _get_s3_config()
    path = cfg["vault_path"].rstrip("/")
    return f"{path}/config.json"


def _get_hint_s3_key() -> str:
    """Get the S3 key for the master password hint file.

    Returns:
        S3 object key for hint.enc
    """
    cfg = _get_s3_config()
    path = cfg["vault_path"].rstrip("/")
    return f"{path}/hint.enc"


def _encrypt_hint(hint: str) -> str:
    """Encrypt a hint using the instance secret.

    Args:
        hint: Plaintext hint string.

    Returns:
        Base64-encoded encrypted hint.
    """
    from cryptography.fernet import Fernet  # type: ignore
    from ..config import get_instance_secret, get_app_salt
    import hashlib

    # Derive a key from instance secret + app salt
    secret = get_instance_secret()
    salt = get_app_salt()
    key_material = hashlib.sha256(secret + salt).digest()
    key = base64.urlsafe_b64encode(key_material)

    cipher = Fernet(key)
    encrypted = cipher.encrypt(hint.encode("utf-8"))
    return encrypted.decode("ascii")


def _decrypt_hint(encrypted_hint: str) -> str:
    """Decrypt a hint using the instance secret.

    Args:
        encrypted_hint: Base64-encoded encrypted hint.

    Returns:
        Plaintext hint string.

    Raises:
        Exception: If decryption fails.
    """
    from cryptography.fernet import Fernet  # type: ignore
    from ..config import get_instance_secret, get_app_salt
    import hashlib

    secret = get_instance_secret()
    salt = get_app_salt()
    key_material = hashlib.sha256(secret + salt).digest()
    key = base64.urlsafe_b64encode(key_material)

    cipher = Fernet(key)
    decrypted = cipher.decrypt(encrypted_hint.encode("ascii"))
    return decrypted.decode("utf-8")


def upload_vault_to_s3(local_vault_path: str) -> bool:
    """Upload the local vault file to S3.

    Args:
        local_vault_path: Path to the local vault.json file.

    Returns:
        True if upload succeeded, False otherwise.

    Security:
        - Uses server-side encryption (SSE-S3)
        - Content-Type set appropriately
    """
    if not is_s3_configured():
        return False

    if not os.path.exists(local_vault_path):
        return False

    try:
        client = _get_s3_client()
        cfg = _get_s3_config()
        s3_key = _get_vault_s3_key()

        with open(local_vault_path, "rb") as f:
            client.put_object(
                Bucket=cfg["bucket"],
                Key=s3_key,
                Body=f,
                ContentType="application/json",
                ServerSideEncryption="AES256",
                Metadata={
                    "uploaded-at": datetime.utcnow().isoformat() + "Z",
                    "source": "secure-vault",
                },
            )
        return True
    except Exception:
        return False


def download_vault_from_s3(local_vault_path: str) -> bool:
    """Download the vault file from S3 to local storage.

    Args:
        local_vault_path: Path to save the downloaded vault.json.

    Returns:
        True if download succeeded, False otherwise.

    Notes:
        - Creates the directory if it doesn't exist
        - Uses atomic write with temp file
        - Sets restrictive permissions (0o600)
    """
    if not is_s3_configured():
        return False

    try:
        client = _get_s3_client()
        cfg = _get_s3_config()
        s3_key = _get_vault_s3_key()

        # Check if object exists
        try:
            client.head_object(Bucket=cfg["bucket"], Key=s3_key)
        except Exception:
            # Object doesn't exist - not an error, just return False
            return False

        # Download to temp file first (atomic operation)
        directory = os.path.dirname(local_vault_path)
        os.makedirs(directory, exist_ok=True)

        with tempfile.NamedTemporaryFile(
            mode="wb", dir=directory, delete=False, suffix=".tmp"
        ) as tmp_file:
            tmp_path = tmp_file.name
            response = client.get_object(Bucket=cfg["bucket"], Key=s3_key)
            tmp_file.write(response["Body"].read())
            tmp_file.flush()
            os.fsync(tmp_file.fileno())

        # Set restrictive permissions and atomically move
        try:
            os.chmod(tmp_path, 0o600)
        except Exception:
            pass

        os.replace(tmp_path, local_vault_path)
        return True
    except Exception:
        # Cleanup temp file if it exists
        try:
            if "tmp_path" in locals() and os.path.exists(tmp_path):
                os.remove(tmp_path)
        except Exception:
            pass
        return False


def upload_config_to_s3(local_config_path: str) -> bool:
    """Upload the local config file to S3.

    Args:
        local_config_path: Path to the local config.json file.

    Returns:
        True if upload succeeded, False otherwise.
    """
    if not is_s3_configured():
        return False

    if not os.path.exists(local_config_path):
        return False

    try:
        client = _get_s3_client()
        cfg = _get_s3_config()
        s3_key = _get_config_s3_key()

        with open(local_config_path, "rb") as f:
            client.put_object(
                Bucket=cfg["bucket"],
                Key=s3_key,
                Body=f,
                ContentType="application/json",
                ServerSideEncryption="AES256",
                Metadata={
                    "uploaded-at": datetime.utcnow().isoformat() + "Z",
                    "source": "secure-vault",
                },
            )
        return True
    except Exception:
        return False


def download_config_from_s3(local_config_path: str) -> bool:
    """Download the config file from S3 to local storage.

    Args:
        local_config_path: Path to save the downloaded config.json.

    Returns:
        True if download succeeded, False otherwise.
    """
    if not is_s3_configured():
        return False

    try:
        client = _get_s3_client()
        cfg = _get_s3_config()
        s3_key = _get_config_s3_key()

        try:
            client.head_object(Bucket=cfg["bucket"], Key=s3_key)
        except Exception:
            return False

        directory = os.path.dirname(local_config_path)
        os.makedirs(directory, exist_ok=True)

        with tempfile.NamedTemporaryFile(
            mode="wb", dir=directory, delete=False, suffix=".tmp"
        ) as tmp_file:
            tmp_path = tmp_file.name
            response = client.get_object(Bucket=cfg["bucket"], Key=s3_key)
            tmp_file.write(response["Body"].read())
            tmp_file.flush()
            os.fsync(tmp_file.fileno())

        try:
            os.chmod(tmp_path, 0o600)
        except Exception:
            pass

        os.replace(tmp_path, local_config_path)
        return True
    except Exception:
        try:
            if "tmp_path" in locals() and os.path.exists(tmp_path):
                os.remove(tmp_path)
        except Exception:
            pass
        return False


def save_hint_to_s3(hint: str) -> bool:
    """Save an encrypted master password hint to S3.

    Args:
        hint: Plaintext hint string.

    Returns:
        True if upload succeeded, False otherwise.

    Security:
        - Hint is encrypted with instance secret before upload
        - Uses server-side encryption
    """
    if not is_s3_configured():
        return False

    if not hint or not hint.strip():
        return False

    try:
        client = _get_s3_client()
        cfg = _get_s3_config()
        s3_key = _get_hint_s3_key()

        # Encrypt the hint before uploading
        encrypted_hint = _encrypt_hint(hint.strip())

        client.put_object(
            Bucket=cfg["bucket"],
            Key=s3_key,
            Body=encrypted_hint.encode("utf-8"),
            ContentType="application/octet-stream",
            ServerSideEncryption="AES256",
            Metadata={
                "uploaded-at": datetime.utcnow().isoformat() + "Z",
                "source": "secure-vault",
                "encrypted": "true",
            },
        )
        return True
    except Exception:
        return False


def get_hint_from_s3() -> Optional[str]:
    """Retrieve and decrypt the master password hint from S3.

    Returns:
        Decrypted hint string, or None if not found or decryption fails.

    Notes:
        If decryption fails (e.g., due to instance secret change), the invalid
        hint is automatically deleted from S3 to prevent confusion.
    """
    if not is_s3_configured():
        return None

    try:
        client = _get_s3_client()
        cfg = _get_s3_config()
        s3_key = _get_hint_s3_key()

        try:
            response = client.get_object(Bucket=cfg["bucket"], Key=s3_key)
            encrypted_hint = response["Body"].read().decode("utf-8")
            try:
                return _decrypt_hint(encrypted_hint)
            except Exception:
                # Decryption failed - likely instance secret changed
                # Delete the invalid hint to prevent confusion
                try:
                    client.delete_object(Bucket=cfg["bucket"], Key=s3_key)
                except Exception:
                    pass
                return None
        except Exception:
            return None
    except Exception:
        return None


def delete_hint_from_s3() -> bool:
    """Delete the master password hint from S3.

    Returns:
        True if deletion succeeded or hint didn't exist.
    """
    if not is_s3_configured():
        return False

    try:
        client = _get_s3_client()
        cfg = _get_s3_config()
        s3_key = _get_hint_s3_key()

        client.delete_object(Bucket=cfg["bucket"], Key=s3_key)
        return True
    except Exception:
        return False


def sync_to_s3(vault_path: str, config_path: Optional[str] = None) -> Tuple[bool, str]:
    """Sync local vault and config to S3.

    Args:
        vault_path: Path to local vault.json.
        config_path: Optional path to local config.json.

    Returns:
        Tuple of (success, message).
    """
    if not is_s3_configured():
        return False, "S3 not configured"

    results = []
    success = True

    # Upload vault
    if os.path.exists(vault_path):
        vault_ok = upload_vault_to_s3(vault_path)
        results.append(f"Vault: {'✓' if vault_ok else '✗'}")
        success = success and vault_ok
    else:
        results.append("Vault: skipped (not found)")

    # Upload config if provided
    if config_path and os.path.exists(config_path):
        config_ok = upload_config_to_s3(config_path)
        results.append(f"Config: {'✓' if config_ok else '✗'}")
        success = success and config_ok

    return success, " | ".join(results)


def sync_from_s3(
    vault_path: str, config_path: Optional[str] = None
) -> Tuple[bool, str]:
    """Sync vault and config from S3 to local storage.

    Args:
        vault_path: Path to save local vault.json.
        config_path: Optional path to save local config.json.

    Returns:
        Tuple of (success, message).
    """
    if not is_s3_configured():
        return False, "S3 not configured"

    results = []
    vault_ok = download_vault_from_s3(vault_path)
    results.append(f"Vault: {'✓' if vault_ok else '✗ (not in S3)'}")

    if config_path:
        config_ok = download_config_from_s3(config_path)
        results.append(f"Config: {'✓' if config_ok else '✗ (not in S3)'}")

    # At least vault success counts as overall success
    return vault_ok, " | ".join(results)


def get_s3_status() -> Dict[str, Any]:
    """Get S3 configuration and sync status.

    Returns:
        Dict with S3 status information:
        - configured: Whether S3 is configured
        - bucket: S3 bucket name (masked)
        - region: AWS region
        - vault_path: S3 path prefix
        - vault_exists: Whether vault exists in S3
        - config_exists: Whether config exists in S3
        - hint_exists: Whether hint exists in S3
        - last_check: Timestamp of this check
    """
    result = {
        "configured": is_s3_configured(),
        "bucket": "",
        "region": "",
        "vault_path": "",
        "vault_exists": False,
        "config_exists": False,
        "hint_exists": False,
        "last_check": datetime.utcnow().isoformat() + "Z",
    }

    if not result["configured"]:
        return result

    try:
        cfg = _get_s3_config()
        # Mask bucket name for security
        bucket = cfg["bucket"]
        result["bucket"] = f"{bucket[:3]}...{bucket[-3:]}" if len(bucket) > 6 else "***"
        result["region"] = cfg["region"]
        result["vault_path"] = cfg["vault_path"]

        client = _get_s3_client()

        # Check vault existence
        try:
            client.head_object(Bucket=cfg["bucket"], Key=_get_vault_s3_key())
            result["vault_exists"] = True
        except Exception:
            pass

        # Check config existence
        try:
            client.head_object(Bucket=cfg["bucket"], Key=_get_config_s3_key())
            result["config_exists"] = True
        except Exception:
            pass

        # Check hint existence
        try:
            client.head_object(Bucket=cfg["bucket"], Key=_get_hint_s3_key())
            result["hint_exists"] = True
        except Exception:
            pass

    except Exception:
        pass

    return result


def initialize_from_s3(vault_path: str, config_path: str) -> bool:
    """Initialize local vault from S3 on application startup.

    Downloads vault from S3 if it exists, otherwise creates an empty local vault.
    This should be called during application initialization.

    Args:
        vault_path: Path for local vault.json.
        config_path: Path for local config.json.

    Returns:
        True if initialization succeeded (either downloaded or created empty).
    """
    if not is_s3_configured():
        return True  # Not an error - S3 is optional

    # Try to download from S3
    vault_downloaded = download_vault_from_s3(vault_path)

    if not vault_downloaded:
        # No vault in S3 - create empty local one and upload
        if not os.path.exists(vault_path):
            directory = os.path.dirname(vault_path)
            os.makedirs(directory, exist_ok=True)
            with open(vault_path, "w", encoding="utf-8") as f:
                json.dump({}, f)
            try:
                os.chmod(vault_path, 0o600)
            except Exception:
                pass
            # Upload the empty vault to S3
            upload_vault_to_s3(vault_path)

    # Try to download config from S3 (don't fail if not found)
    download_config_from_s3(config_path)

    return True
