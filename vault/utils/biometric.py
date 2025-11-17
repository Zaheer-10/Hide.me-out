"""Biometric unlock stubs.

Provides OS-specific placeholders for future integration with Windows Hello,
macOS Keychain + TouchID, and Android fingerprint. Linux defaults to master
password. The implementation stores an encrypted master password blob in a
SQLite DB; encryption/decryption logic is handled elsewhere.
"""

from __future__ import annotations

import os
import sqlite3
from typing import Optional


def _ensure_db(path: str) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    conn = sqlite3.connect(path)
    try:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS biometric_data (
                id INTEGER PRIMARY KEY,
                platform TEXT NOT NULL,
                encrypted_master_blob BLOB NOT NULL,
                biometric_key_id TEXT,
                created_at TEXT NOT NULL,
                last_used TEXT
            )
            """
        )
        conn.commit()
    finally:
        conn.close()


def store_encrypted_master_blob(db_path: str, platform: str, blob: bytes, key_id: Optional[str] = None) -> bool:
    """Store encrypted master password blob for biometric unlock.

    Args:
        db_path: Path to SQLite DB.
        platform: Platform identifier (e.g., "macos", "windows", "linux", "android").
        blob: Encrypted bytes of the master password.
        key_id: Optional platform-specific key identifier.

    Returns:
        True on success.
    """
    try:
        _ensure_db(db_path)
        conn = sqlite3.connect(db_path)
        try:
            conn.execute(
                "INSERT INTO biometric_data(platform, encrypted_master_blob, biometric_key_id, created_at) VALUES (?, ?, ?, datetime('now'))",
                (platform, blob, key_id),
            )
            conn.commit()
            return True
        finally:
            conn.close()
    except Exception:
        return False


def unlock_master_password(db_path: str, platform: str) -> Optional[bytes]:
    """Retrieve the encrypted master blob for biometric-based unlock.

    Args:
        db_path: Path to SQLite DB.
        platform: Platform identifier.

    Returns:
        Encrypted master blob bytes if available, else None.

    Notes:
        Actual biometric verification must be implemented per-OS; this stub
        only manages storage.
    """
    try:
        conn = sqlite3.connect(db_path)
        try:
            cur = conn.execute("SELECT encrypted_master_blob FROM biometric_data WHERE platform = ? ORDER BY last_used DESC, created_at DESC LIMIT 1", (platform,))
            row = cur.fetchone()
            return row[0] if row else None
        finally:
            conn.close()
    except Exception:
        return None