import os
import tempfile
from vault.vault import VaultEngine
from vault.config import SecurityPolicy


def test_add_and_get_entry():
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "vault.json")
        engine = VaultEngine(policy=SecurityPolicy(), audit=None, vault_path=path)
        ok = engine.add_entry("StrongMasterPass123!", "github", "user", "pass", "https://github.com")
        assert ok
        res = engine.get_entry("StrongMasterPass123!", "github")
        assert res is not None
        assert res["username"] == "user"
        assert res["password"] == "pass"


def test_search_entries():
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "vault.json")
        engine = VaultEngine(policy=SecurityPolicy(), audit=None, vault_path=path)
        engine.add_entry("StrongMasterPass123!", "gmail", "alice", "pw1", "mail")
        engine.add_entry("StrongMasterPass123!", "bank", "bob", "pw2", "finance")
        res = engine.search_entries("StrongMasterPass123!", "bob")
        assert len(res) == 1
        assert res[0]["service_name"] == "bank"


def test_update_and_delete_entry():
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "vault.json")
        engine = VaultEngine(policy=SecurityPolicy(), audit=None, vault_path=path)
        engine.add_entry("StrongMasterPass123!", "service", "u", "p", "s")
        ok = engine.update_entry("StrongMasterPass123!", "service", username="u2")
        assert ok
        res = engine.get_entry("StrongMasterPass123!", "service")
        assert res["username"] == "u2"
        ok = engine.delete_entry("StrongMasterPass123!", "service")
        assert ok
        assert engine.get_entry("StrongMasterPass123!", "service") is None