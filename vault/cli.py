"""Command-line interface for the secure vault.

Provides a simple interactive menu with secure input via `getpass`.
"""

from __future__ import annotations

import getpass
import os

from .vault import add_entry, get_entry, search_entries


def _prompt(text: str) -> str:
    return input(text).strip()


def _prompt_secret(text: str) -> str:
    return getpass.getpass(text).strip()


def main() -> None:
    while True:
        print("\nSecure Vault CLI")
        print("1. Add entry")
        print("2. Get entry")
        print("3. Search")
        print("4. Export vault")
        print("5. Import vault")
        print("6. Quit")
        choice = _prompt("Select option: ")

        if choice == "1":
            master = _prompt_secret("Master password: ")
            service = _prompt("Service name: ")
            username = _prompt("Username: ")
            password = _prompt_secret("Password: ")
            source = _prompt("Source info (optional): ")
            ok = add_entry(master, service, username, password, source)
            print("Added." if ok else "Failed to add.")
        elif choice == "2":
            master = _prompt_secret("Master password: ")
            service = _prompt("Service name: ")
            entry = get_entry(master, service)
            if entry:
                print("\nDecrypted Entry:")
                print(entry)
            else:
                print("Not found or wrong master password.")
        elif choice == "3":
            master = _prompt_secret("Master password: ")
            keyword = _prompt("Keyword: ")
            results = search_entries(master, keyword)
            print(f"Found {len(results)} entries:")
            for r in results:
                print(r)
        elif choice == "4":
            path = _prompt("Export path: ")
            os.environ["VAULT_MASTER_PASSWORD"] = _prompt_secret("Master password (for export): ")
            from .vault import export_vault

            ok = export_vault(path)
            print("Exported." if ok else "Export failed.")
        elif choice == "5":
            path = _prompt("Import path: ")
            merge = _prompt("Merge with existing? (y/N): ").lower() == "y"
            os.environ["VAULT_MASTER_PASSWORD"] = _prompt_secret("Master password (for import): ")
            from .vault import import_vault

            ok = import_vault(path, merge=merge)
            print("Imported." if ok else "Import failed.")
        elif choice == "6":
            print("Goodbye.")
            return
        else:
            print("Invalid option.")


if __name__ == "__main__":
    main()