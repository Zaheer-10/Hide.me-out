"""
Vault package for the Secure Sensitive Data Encrypt application.

This package provides the core encryption engine, command-line interface,
desktop and web user interfaces, and supporting utilities for secure storage
and retrieval of sensitive credentials using a zero-knowledge architecture.

Security Overview:
- Zero-knowledge: The master password is never stored, transmitted, or logged.
- Per-entry encryption: Each entry uses a unique 16-byte salt and key derived
  via PBKDF2-HMAC-SHA256 with 200,000+ iterations.
- Authenticated encryption: All data fields are encrypted with Fernet
  (AES-CBC + HMAC-SHA256), providing confidentiality and integrity.
- Obfuscated metadata: Service names are stored as base64(service_name + salt)
  to avoid leaking semantics.
- Atomic I/O: All vault writes use temp files and atomic renames to prevent
  corruption and ensure durability.

Threat Model (High-Level):
- Attacker with local file access: Cannot decrypt without the master password;
  service names obfuscated to limit metadata leakage.
- Tampering with vault file: Authenticated encryption detects modification;
  decryption fails safely.
- Side-channel logging/exfiltration: Logging excludes secrets; audit trail
  stores minimal metadata only.
- Brute force of master password: PBKDF2 iterations provide computational
  cost; encourage strong master passwords and optional biometric unlock.

This module-level docstring intentionally documents architecture and security
considerations to support enterprise-grade review and compliance.
"""

__all__ = [
    "config",
    "vault",
]