"""Cloud sync utilities for Proton Drive local folder.

Only the encrypted vault file is synced. No decryption occurs.

Security Constraints:
- Never send unencrypted data externally.
- Only copy `vault.json` as-is to the configured Proton Drive path.
"""

from __future__ import annotations

import os
import shutil


def sync_encrypted_vault(vault_path: str, target_dir: str) -> bool:
    """Sync the encrypted vault file to a Proton Drive local folder.

    Args:
        vault_path: Path to the local encrypted `vault.json`.
        target_dir: Path to the Proton Drive local sync folder.

    Returns:
        True if syncing succeeded; False otherwise.

    Notes:
        This function performs no decryption and simply copies the file.
    """
    if not target_dir:
        return False
    try:
        os.makedirs(target_dir, exist_ok=True)
        shutil.copy2(vault_path, os.path.join(target_dir, os.path.basename(vault_path)))
        return True
    except Exception:
        return False
