I want you to generate a complete, secure password-vault application with the following requirements.
You must follow the exact architecture, security rules, and constraints listed here.

---

# 🛡️ **1. SECURITY REQUIREMENTS (MANDATORY)**

You MUST implement these security rules:

### 1. Master password

* The user has **one master password**.
* It is NEVER stored directly.

### 2. Key derivation

* Use **PBKDF2-HMAC-SHA256**
* 200,000 iterations (or more)
* 32-byte derived key
* Per-entry random 16-byte salt

### 3. Encryption

* Use `cryptography.fernet.Fernet`
* Encrypt each password separately
* Use the derived key + the per-entry salt

### 4. Obfuscation of service names

* Store service names as:
  `base64( service_name + salt )`
* Avoid revealing “gmail”, “bank”, etc.

### 5. Vault storage

* Store encrypted entries in `vault.json`
* Format:

```
{
  "obfuscated_key": {
      "username": "...",
      "password": "...(fernet encrypted)...",
      "salt": "...base64...",
      "source": the encrytion of link or source url or source text.
  },
  ...
}
```

### 6. Do NOT store any master-key, symmetric key, or unencrypted data.

### 7. All file operations must be safe (atomic write or temp-file swap).

---

# 📁 **2. PROJECT STRUCTURE**

Generate code for this folder layout:

```
vault/
│── vault.py                 # core encryption/decryption logic
│── cli.py                   # CLI program
│── gui_streamlit.py           # Desktop GUI (streamlit)
│── gui_web.py               # HTML Web UI (FastAPI)
│── storage/
│     └── vault.json         # encrypted vault file
│── utils/
      ├── cloud_sync.py      # Proton Drive sync (encrypted file only)
      ├── biometric.py       # OS-specific biometric unlock
      └── obfuscation.py     # service-name obfuscation helpers
```

Populate every file with complete working code.

---

# 🧠 **3. FEATURES REQUIRED**

### ✔ Core Vault Functions (vault.py)

Implement functions:

* `add_entry(master, service, username, password)`
* `get_entry(master, service)`
* `search_entries(master, keyword)`
* `export_vault(path)`
* `import_vault(path)`
* plus: `derive_key`, `obfuscate`, `deobfuscate`, `load_vault`, `save_vault`

### ✔ CLI (cli.py)

Menu with:

1. Add entry
2. Get entry
3. Search
4. Export vault
5. Import vault
6. Quit

Uses `getpass` for sensitive input.

### ✔ GUI: Tkinter (gui_tkinter.py)

A clean UI with:

* Master password prompt
* Add entry
* Get entry
* Search
* Export/Import

### ✔ GUI: Web/HTML (gui_web.py)

* Fastapi backend
* HTML templates (inline or folder)
* Local-only server
* No external CDN
* Routes: `/`, `/add`, `/get`, `/search`, `/export`, `/import`

### ✔ Obfuscation (utils/obfuscation.py)

Separated helper functions:

* `obfuscate_service_name(name, salt)`
* `deobfuscate_service_name(obf, salt)`

### ✔ Proton Drive Sync (utils/cloud_sync.py)

* Sync encrypted `vault.json` to a Proton Drive local-sync folder
* Must NOT decrypt the file
* Allow both manual sync and auto-sync on save

### ✔ Biometric Unlock (utils/biometric.py)

Provide stubs for:

* Windows Hello
* macOS Keychain + TouchID
* Linux (no default, fallback to master password)
* Android (fingerprint via Kivy if mobile app)

Logic:

* Biometrics decrypt a stored **encrypted master password blob**
* Resulting plaintext master password is NOT stored

### ✔ Config

Use a small config JSON or constants for:

* Proton Drive sync path
* Biometric storage path

---

# 🛡️ **4. SECURITY CONSTRAINTS TO FOLLOW**

You MUST follow these rules:

### 🚫 Forbidden

* No custom cryptography
* No XOR “encryption”
* No reuse of salts
* No global symmetric key
* No storing master password
* No weak hashing (MD5/SHA1)
* No logging passwords
* No sending data externally
* No cloud storage except the encrypted vault file

### ✔ Required

* Per-entry salt
* Unique key per entry
* Strong KDF
* Authenticated encryption only
* Constant-time operations where relevant

---

# 🎨 **5. PROVIDE COMPLETE OUTPUT**

You must output:

1. **All Python files fully implemented**
2. **HTML files (if applicable)**
3. **Instructions to run the app**
4. **Instructions to sync with Proton Drive**
5. **Instructions to enable biometric unlock for each OS**

Make sure the entire project is runnable immediately.

The main goal is I have enumber of usernames, passwords which is hard to rembere and scared to keep to save somewhere as a plain text and all, instead i want to build a secur system where one this way can view those passowrd like multi level security etc.

These are the inputs that we need to collect from the user as an input:

master_passowrd : (think about initally how user can add / forgot/reset/ etc)
service_name
service_info : it can be links, or source text
user_name:
password:


so while fetching the user as to get the decrypted info:

{
    "service_name:
    "user_name":
    "passoword":
    "source_info":
}

For dependcy manger use uv or poetry whichever is best and python version <3.12