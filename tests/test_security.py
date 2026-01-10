import os
import stat
import json
import pytest
import sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from vault.config import _atomic_write_json
from vault.vault import VaultEngine, SecurityPolicy

def test_atomic_write_permissions(tmp_path):
    """Verify that _atomic_write_json creates files with 0o600 permissions."""
    target = tmp_path / "test_config.json"
    data = {"foo": "bar"}
    _atomic_write_json(str(target), data)
    
    assert target.exists()
    mode = os.stat(target).st_mode
    # Check that only owner has read/write permissions (0o600)
    # On some systems/filesystems, exact mode match might vary, but we check for no group/other access
    assert stat.S_IMODE(mode) & 0o077 == 0

def test_save_vault_permissions(tmp_path):
    """Verify that save_vault creates files with 0o600 permissions."""
    vault_path = tmp_path / "vault.json"
    engine = VaultEngine(SecurityPolicy(), None, str(vault_path))
    engine.save_vault({"foo": "bar"})
    
    assert vault_path.exists()
    mode = os.stat(vault_path).st_mode
    assert stat.S_IMODE(mode) & 0o077 == 0

def test_export_vault_permissions(tmp_path, monkeypatch):
    """Verify that export_vault creates files with 0o600 permissions."""
    # Setup vault with one entry
    vault_path = tmp_path / "vault.json"
    export_path = tmp_path / "export.json"
    
    # Mock environment variable for export
    monkeypatch.setenv("VAULT_MASTER_PASSWORD", "test_master_password")
    
    # Initialize engine and add entry
    engine = VaultEngine(SecurityPolicy(), None, str(vault_path))
    # We need to mock the module-level _engine for export_vault to work as it uses the global instance
    # However, since export_vault is a module level function in vault.py that uses _engine,
    # we can't easily swap the _engine instance it uses without patching vault.vault._engine
    
    # Instead of full integration test which is complex due to global state, 
    # let's test the permission logic by calling the function if possible, 
    # or just rely on the unit tests above for the shared logic if export_vault uses similar mechanisms.
    # But export_vault implements its own open(), so we should test it.
    
    # We'll patch the _engine in vault.py
    import vault.vault
    vault.vault._engine = engine
    
    # Add a dummy entry to ensure export has content (though empty vault is fine too)
    engine.save_vault({}) 
    
    from vault.vault import export_vault
    assert export_vault(str(export_path))
    
    assert export_path.exists()
    mode = os.stat(export_path).st_mode
    assert stat.S_IMODE(mode) & 0o077 == 0
