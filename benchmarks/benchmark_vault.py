import os
import time
import tempfile
from vault.vault import VaultEngine
from vault.config import SecurityPolicy


def run_benchmark(iterations: int = 100):
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "vault.json")
        engine = VaultEngine(policy=SecurityPolicy(), audit=None, vault_path=path)
        start = time.time()
        for i in range(iterations):
            engine.add_entry("StrongMasterPass123!", f"svc{i}", "u", "p", "s")
            engine.get_entry("StrongMasterPass123!", f"svc{i}")
        end = time.time()
        print(f"Iterations: {iterations}, Total: {end - start:.3f}s, Avg: {(end - start)/iterations:.6f}s")


if __name__ == "__main__":
    run_benchmark()