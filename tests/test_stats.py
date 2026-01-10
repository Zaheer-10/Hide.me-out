import os
import sys
import pytest
import json

# Add project root to sys.path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from vault.config import load_config, save_config, increment_stat
from vault.vault import VaultEngine, SecurityPolicy, add_entry, delete_entry, import_vault

@pytest.fixture
def mock_env(tmp_path, monkeypatch):
    """Setup mock environment for testing."""
    # Mock config and vault paths
    config_path = tmp_path / "config.json"
    vault_path = tmp_path / "vault.json"
    
    # Patch default paths in config module
    monkeypatch.setattr("vault.config.DEFAULT_CONFIG_PATH", str(config_path))
    monkeypatch.setattr("vault.vault.DEFAULT_VAULT_PATH", str(vault_path))
    
    # Patch _engine in vault module to use temp paths
    policy = SecurityPolicy()
    engine = VaultEngine(policy, None, str(vault_path))
    monkeypatch.setattr("vault.vault._engine", engine)
    
    return tmp_path

def test_increment_stat(mock_env):
    """Test increment_stat helper."""
    assert increment_stat("entries_created_count") == 1
    assert increment_stat("entries_created_count", 2) == 3
    
    cfg = load_config()
    assert cfg["entries_created_count"] == 3

def test_add_entry_stats(mock_env):
    """Test that add_entry increments entries_created_count."""
    # Initial state
    cfg = load_config()
    initial_count = cfg.get("entries_created_count", 0)
    
    # Add entry with strong password
    add_entry("StrongMasterPass1!", "service1", "user", "pass")
    
    # Verify increment
    cfg = load_config()
    assert cfg["entries_created_count"] == initial_count + 1

def test_delete_entry_stats(mock_env):
    """Test that delete_entry increments entries_deleted_count."""
    # Add entry first
    add_entry("StrongMasterPass1!", "service1", "user", "pass")
    
    # Initial delete count
    cfg = load_config()
    initial_delete = cfg.get("entries_deleted_count", 0)
    
    # Delete entry
    delete_entry("StrongMasterPass1!", "service1")
    
    # Verify increment
    cfg = load_config()
    assert cfg["entries_deleted_count"] == initial_delete + 1

def test_import_vault_stats(mock_env, monkeypatch):
    """Test that import_vault increments entries_created_count."""
    # Create import file
    import_path = mock_env / "import.json"
    data = [
        {"service_name": "s1", "username": "u1", "password": "p1"},
        {"service_name": "s2", "username": "u2", "password": "p2"},
    ]
    with open(import_path, "w") as f:
        json.dump(data, f)
    
    # Set master password env var
    monkeypatch.setenv("VAULT_MASTER_PASSWORD", "StrongMasterPass1!")
    
    # Initial count
    cfg = load_config()
    initial_count = cfg.get("entries_created_count", 0)
    
    # Import
    import_vault(str(import_path))
    
    # Verify increment (2 entries imported)
    cfg = load_config()
    assert cfg["entries_created_count"] == initial_count + 2
