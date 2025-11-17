"""AES-256-GCM helpers for encrypting/decrypting payloads.

Implements application-instance-bound encryption using a derived key from an
instance secret and an application-specific salt. This ensures encrypted keys
can only be decrypted by the application instance that created them.
"""

from __future__ import annotations

# pyright: reportMissingImports=false, reportMissingTypeStubs=false
# mypy: ignore-missing-imports

import os
import base64
from typing import Tuple

# type: ignore
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC  # type: ignore
from cryptography.hazmat.primitives import hashes  # type: ignore
from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # type: ignore


def derive_aes_key(instance_secret: bytes, app_salt: bytes, iterations: int = 300_000) -> bytes:
    """Derive a 32-byte AES-256 key using PBKDF2-HMAC-SHA256.

    Args:
        instance_secret: High-entropy secret unique to application instance.
        app_salt: Application-specific salt (not secret) to bind keys to app.
        iterations: PBKDF2 iteration count.

    Returns:
        32-byte key suitable for AES-256.
    """
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=app_salt, iterations=iterations)
    return kdf.derive(instance_secret)


def aes_gcm_encrypt(key: bytes, plaintext: bytes, aad: bytes | None = None) -> Tuple[str, str]:
    """Encrypt bytes with AES-256-GCM.

    Args:
        key: 32-byte AES key.
        plaintext: Data to encrypt.
        aad: Optional additional authenticated data.

    Returns:
        Tuple of (nonce_b64, ciphertext_b64).
    """
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)  # 96-bit nonce
    ct = aesgcm.encrypt(nonce, plaintext, aad)
    return base64.urlsafe_b64encode(nonce).decode("ascii"), base64.urlsafe_b64encode(ct).decode("ascii")


def aes_gcm_decrypt(key: bytes, nonce_b64: str, ciphertext_b64: str, aad: bytes | None = None) -> bytes:
    """Decrypt bytes with AES-256-GCM.

    Args:
        key: 32-byte AES key.
        nonce_b64: Base64-encoded nonce.
        ciphertext_b64: Base64-encoded ciphertext.
        aad: Optional additional authenticated data.

    Returns:
        Decrypted plaintext bytes.
    """
    aesgcm = AESGCM(key)
    nonce = base64.urlsafe_b64decode(nonce_b64.encode("ascii"))
    ct = base64.urlsafe_b64decode(ciphertext_b64.encode("ascii"))
    return aesgcm.decrypt(nonce, ct, aad)