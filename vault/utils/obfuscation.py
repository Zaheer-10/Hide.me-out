"""Service name obfuscation helpers.

Implements base64(service_name + salt) and safe reversal, keeping salt
separate for deobfuscation.

Threat Model:
- Prevents casual metadata leakage from raw vault.json entries.
- Not a cryptographic guarantee; serves as obscurity to limit semantics.
"""

from __future__ import annotations

import base64


def obfuscate_service_name(service_name: str, salt: bytes) -> str:
    """Obfuscate a service name using base64(service_name + salt).

    Args:
        service_name: Plain service name string.
        salt: Unique 16-byte salt for this entry.

    Returns:
        Base64-encoded string representing the obfuscated service key.

    Raises:
        ValueError: If salt is not 16 bytes.
    """
    if not isinstance(salt, (bytes, bytearray)) or len(salt) != 16:
        raise ValueError("Salt must be 16 bytes")
    raw = service_name.encode("utf-8") + bytes(salt)
    return base64.urlsafe_b64encode(raw).decode("ascii")


def deobfuscate_service_name(obfuscated_key: str, salt: bytes) -> str:
    """Reverse obfuscation to recover the original service name.

    Args:
        obfuscated_key: Base64 string produced by `obfuscate_service_name`.
        salt: The same 16-byte salt used during obfuscation.

    Returns:
        The original service name string.
    """
    raw = base64.urlsafe_b64decode(obfuscated_key.encode("ascii"))
    name_bytes = raw[:-16]
    return name_bytes.decode("utf-8")