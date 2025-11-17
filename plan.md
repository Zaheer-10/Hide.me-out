# 🔐 Secure Password Vault Application - Comprehensive Implementation Plan

## 📋 Table of Contents
1. [Project Overview](#project-overview)
2. [Architecture Design](#architecture-design)
3. [Security Architecture](#security-architecture)
4. [Master Password Management](#master-password-management)
5. [Data Model & Storage](#data-model--storage)
6. [Module Specifications](#module-specifications)
7. [API & Interface Design](#api--interface-design)
8. [User Interfaces](#user-interfaces)
9. [Error Handling & Edge Cases](#error-handling--edge-cases)
10. [Dependencies & Configuration](#dependencies--configuration)
11. [Testing Strategy](#testing-strategy)
12. [Deployment & Usage](#deployment--usage)
13. [Future Enhancements](#future-enhancements)

---

## 🎯 Project Overview

### Purpose
A secure, multi-level encrypted password vault application that allows users to store and manage sensitive credentials (usernames, passwords, service information) with enterprise-grade security. The application provides multiple interfaces (CLI, Streamlit GUI, Web UI) and supports biometric authentication and cloud synchronization.

### Core Principles
- **Zero-knowledge architecture**: Master password never stored
- **Per-entry encryption**: Each credential encrypted with unique key
- **Service name obfuscation**: Prevent metadata leakage
- **Multi-level security**: Master password + optional biometrics
- **Atomic operations**: Safe file I/O with rollback capability
- **Local-first**: All processing happens locally, only encrypted files sync

### User Inputs Required
- **master_password**: Single master key for vault access
- **service_name**: Name/identifier of the service (e.g., "Gmail", "Bank Account")
- **service_info**: Source URL, link, or descriptive text about the service
- **username**: Username/email for the service
- **password**: Password for the service

### Output Format
When fetching an entry, user receives:
```json
{
    "service_name": "decrypted service name",
    "username": "decrypted username",
    "password": "decrypted password",
    "source_info": "decrypted service info"
}
```

---

## 🏗️ Architecture Design

### System Architecture Layers

```
┌─────────────────────────────────────────────────────────┐
│                    User Interface Layer                  │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐             │
│  │   CLI    │  │ Streamlit │  │  Web UI  │             │
│  └────┬─────┘  └─────┬─────┘  └─────┬─────┘             │
└───────┼──────────────┼──────────────┼───────────────────┘
        │              │              │
┌───────┴──────────────┴──────────────┴───────────────────┐
│                  Business Logic Layer                     │
│  ┌──────────────────────────────────────────────────┐   │
│  │              vault.py (Core Engine)               │   │
│  │  - Key derivation                                 │   │
│  │  - Encryption/Decryption                          │   │
│  │  - Vault operations (CRUD)                       │   │
│  │  - Entry management                              │   │
│  └──────────────────────────────────────────────────┘   │
└───────┬───────────────────────────────────────────────────┘
        │
┌───────┴───────────────────────────────────────────────────┐
│                  Utility Layer                             │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐    │
│  │ obfuscation  │  │  biometric   │  │ cloud_sync   │    │
│  └──────────────┘  └──────────────┘  └──────────────┘    │
└───────┬───────────────────────────────────────────────────┘
        │
┌───────┴───────────────────────────────────────────────────┐
│                  Storage Layer                              │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐    │
│  │  vault.json   │  │   config.json │  │ biometric.db │    │
│  └──────────────┘  └──────────────┘  └──────────────┘    │
└───────────────────────────────────────────────────────────┘
```

### Data Flow

#### Adding an Entry
```
User Input → Validate → Generate Salt → Derive Key → Encrypt Fields → 
Obfuscate Service Name → Store in vault.json → Atomic Write → (Optional) Cloud Sync
```

#### Retrieving an Entry
```
User Input (Master Password) → Validate → Load vault.json → 
Iterate Entries → Deobfuscate Service Names → Match → 
Derive Key → Decrypt Entry → Return Plaintext
```

#### Biometric Unlock Flow
```
Biometric Auth → Decrypt Master Password Blob → 
Use Master Password → Standard Unlock Flow
```

---

## 🛡️ Security Architecture

### 1. Master Password Handling

#### Initial Setup
- **First Run Detection**: Check if `vault.json` exists
- **Master Password Creation**:
  - Prompt user to create master password
  - Enforce minimum requirements (8+ chars, complexity optional but recommended)
  - Confirm password (re-enter for verification)
  - Store a **verification hash** (PBKDF2-HMAC-SHA256, 200k iterations) in `config.json`
  - This hash is ONLY used for verification, never for decryption

#### Master Password Verification
- User enters master password
- Derive key using PBKDF2
- Use derived key to attempt decryption of a test entry or verification hash
- If successful, master password is correct

#### Master Password Reset/Recovery
**⚠️ CRITICAL**: Since master password is never stored, reset means:
1. **Option A: Recovery Phrase** (Recommended)
   - Generate 12-word BIP39 recovery phrase during initial setup
   - Encrypt recovery phrase with master password
   - Store encrypted recovery phrase in `config.json`
   - User can recover master password using recovery phrase
   - Recovery phrase must be shown once and stored securely by user

2. **Option B: Full Reset** (Destructive)
   - User confirms they want to reset
   - **WARNING**: All encrypted data becomes unrecoverable
   - Delete `vault.json` and `config.json`
   - Start fresh setup

3. **Option C: Export Before Reset**
   - Export vault to encrypted backup file
   - Reset vault
   - User can import backup if they remember old master password

#### Master Password Change
- User provides current master password
- User provides new master password
- Re-encrypt all entries with new master password:
  - Load all entries with old master password
  - For each entry: decrypt with old key, encrypt with new key
  - Update verification hash
  - Atomic write to vault.json

### 2. Key Derivation Process

#### Per-Entry Key Derivation
```
Input: master_password (string), entry_salt (16 bytes, random)
Process:
  1. Convert master_password to bytes (UTF-8)
  2. Apply PBKDF2-HMAC-SHA256:
     - Password: master_password bytes
     - Salt: entry_salt (unique per entry)
     - Iterations: 200,000 (configurable, minimum 200k)
     - Key length: 32 bytes
  3. Output: 32-byte derived key
```

#### Key Usage
- Each entry uses its own salt → unique derived key
- Same master password + different salt = different key
- Prevents rainbow table attacks
- Prevents correlation between entries

### 3. Encryption Process

#### Fernet Encryption Details
- **Algorithm**: AES-128 in CBC mode with HMAC-SHA256 authentication
- **Key Format**: 32-byte key (Fernet requires base64url-encoded 32-byte key)
- **Process**:
  1. Derive 32-byte key using PBKDF2
  2. Create Fernet instance with derived key
  3. Encrypt each field separately:
     - `username`: Encrypted → base64 string
     - `password`: Encrypted → base64 string
     - `source`: Encrypted → base64 string
  4. Store encrypted values in vault.json

#### Why Separate Field Encryption?
- Allows partial decryption if needed
- Prevents field correlation
- Better security isolation

### 4. Service Name Obfuscation

#### Obfuscation Process
```
Input: service_name (string), salt (16 bytes, random per entry)
Process:
  1. Concatenate: service_name + salt (as bytes)
  2. Encode to base64
  3. Use as key in vault.json
Output: base64(service_name_bytes + salt_bytes)
```

#### Deobfuscation Process
```
Input: obfuscated_key (base64 string), salt (from entry)
Process:
  1. Decode base64 to bytes
  2. Remove last 16 bytes (salt)
  3. Decode remaining bytes to UTF-8 string
Output: original service_name
```

#### Why Obfuscate?
- Prevents metadata leakage
- Someone with vault.json cannot see service names
- Even with file access, service names are hidden
- Salt ensures same service name → different obfuscated key

### 5. Vault Storage Format

#### vault.json Structure
```json
{
  "obfuscated_service_key_1": {
    "username": "base64_fernet_encrypted_username",
    "password": "base64_fernet_encrypted_password",
    "source": "base64_fernet_encrypted_source_info",
    "salt": "base64_encoded_16_byte_salt",
    "created_at": "ISO8601_timestamp",
    "updated_at": "ISO8601_timestamp"
  },
  "obfuscated_service_key_2": {
    ...
  }
}
```

#### Metadata Fields
- `salt`: Used for key derivation and deobfuscation
- `created_at`: Entry creation timestamp (not encrypted, for sorting)
- `updated_at`: Last modification timestamp (not encrypted)

### 6. Atomic File Operations

#### Safe Write Process
```
1. Create temporary file: vault.json.tmp
2. Write complete JSON to temp file
3. Flush and sync to disk
4. Verify temp file integrity (optional: checksum)
5. Atomic rename: vault.json.tmp → vault.json
6. If any step fails, rollback (delete temp file)
```

#### Why Atomic?
- Prevents partial writes
- Prevents corruption on crash
- Ensures vault.json is always valid JSON
- Allows safe concurrent access (with file locking)

### 7. Security Constraints Implementation

#### Forbidden Practices (Enforcement)
- ✅ No custom crypto: Use only `cryptography` library
- ✅ No XOR: Use Fernet only
- ✅ No salt reuse: Generate new 16-byte random salt per entry
- ✅ No global key: Each entry has unique derived key
- ✅ No master password storage: Only verification hash
- ✅ No weak hashing: PBKDF2-HMAC-SHA256 only
- ✅ No password logging: All logging excludes sensitive data
- ✅ No external transmission: All processing local
- ✅ No unencrypted cloud storage: Only encrypted vault.json syncs

#### Required Practices (Implementation)
- ✅ Per-entry salt: `secrets.token_bytes(16)` for each entry
- ✅ Unique key per entry: master_password + entry_salt → unique key
- ✅ Strong KDF: PBKDF2 with 200k+ iterations
- ✅ Authenticated encryption: Fernet provides authentication
- ✅ Constant-time comparison: Use `secrets.compare_digest()` for password verification

---

## 📁 Data Model & Storage

### Entry Data Model

#### Internal Representation (Plaintext)
```python
{
    "service_name": str,      # User-provided service name
    "username": str,          # Username/email
    "password": str,          # Password
    "source_info": str,       # URL, link, or description
    "created_at": datetime,   # Creation timestamp
    "updated_at": datetime    # Last update timestamp
}
```

#### Stored Representation (Encrypted)
```python
{
    "obfuscated_key": str,    # base64(service_name + salt)
    "username": str,          # Fernet encrypted, base64
    "password": str,          # Fernet encrypted, base64
    "source": str,            # Fernet encrypted, base64
    "salt": str,              # base64 encoded 16-byte salt
    "created_at": str,        # ISO8601 timestamp
    "updated_at": str         # ISO8601 timestamp
}
```

### Configuration Model

#### config.json Structure
```json
{
  "version": "1.0.0",
  "master_password_hash": "base64_pbkdf2_hash_for_verification",
  "pbkdf2_iterations": 200000,
  "proton_drive_path": "/path/to/proton/drive/sync",
  "biometric_enabled": false,
  "biometric_storage_path": "./storage/biometric.db",
  "auto_sync_enabled": false,
  "recovery_phrase_encrypted": "base64_encrypted_recovery_phrase",
  "created_at": "ISO8601_timestamp",
  "last_backup": "ISO8601_timestamp"
}
```

### Biometric Storage Model

#### biometric.db Structure (SQLite)
```sql
CREATE TABLE biometric_data (
    id INTEGER PRIMARY KEY,
    platform TEXT NOT NULL,  -- 'windows', 'macos', 'linux', 'android'
    encrypted_master_blob BLOB NOT NULL,  -- Encrypted master password
    biometric_key_id TEXT,  -- Platform-specific key identifier
    created_at TEXT NOT NULL,
    last_used TEXT
);
```

---

## 🔧 Module Specifications

### 1. vault.py - Core Encryption Engine

#### Responsibilities
- Key derivation using PBKDF2
- Fernet encryption/decryption
- Vault file I/O (load/save)
- Entry CRUD operations
- Vault import/export
- Master password verification

#### Functions Specification

##### `derive_key(master_password: str, salt: bytes, iterations: int = 200000) -> bytes`
- **Purpose**: Derive encryption key from master password
- **Input**: Master password string, 16-byte salt, iteration count
- **Output**: 32-byte derived key
- **Algorithm**: PBKDF2-HMAC-SHA256
- **Error Handling**: Raise ValueError if salt is wrong size

##### `create_fernet_key(derived_key: bytes) -> Fernet`
- **Purpose**: Create Fernet instance from derived key
- **Input**: 32-byte derived key
- **Output**: Fernet cipher instance
- **Error Handling**: Raise ValueError if key is wrong size

##### `encrypt_field(data: str, key: bytes) -> str`
- **Purpose**: Encrypt a single field using Fernet
- **Input**: Plaintext string, 32-byte key
- **Output**: Base64-encoded encrypted string
- **Error Handling**: Handle encryption errors gracefully

##### `decrypt_field(encrypted_data: str, key: bytes) -> str`
- **Purpose**: Decrypt a single field
- **Input**: Base64-encoded encrypted string, 32-byte key
- **Output**: Plaintext string
- **Error Handling**: Raise DecryptionError if key is wrong or data corrupted

##### `load_vault(vault_path: str = "./storage/vault.json") -> dict`
- **Purpose**: Load vault.json file
- **Input**: Path to vault file
- **Output**: Dictionary of vault entries
- **Error Handling**: 
  - Return empty dict if file doesn't exist
  - Raise JSONDecodeError if invalid JSON
  - Handle file permission errors

##### `save_vault(vault_data: dict, vault_path: str = "./storage/vault.json") -> bool`
- **Purpose**: Save vault to file atomically
- **Input**: Vault dictionary, file path
- **Output**: True if successful, False otherwise
- **Error Handling**:
  - Create temp file, write, atomic rename
  - Rollback on failure
  - Handle disk full errors

##### `add_entry(master_password: str, service_name: str, username: str, password: str, source_info: str) -> bool`
- **Purpose**: Add new entry to vault
- **Input**: All entry fields
- **Output**: True if successful
- **Process**:
  1. Generate 16-byte random salt
  2. Derive key using master_password + salt
  3. Encrypt username, password, source_info
  4. Obfuscate service_name
  5. Load vault, add entry, save vault
- **Error Handling**: Validate inputs, handle duplicate service names

##### `get_entry(master_password: str, service_name: str) -> dict | None`
- **Purpose**: Retrieve and decrypt an entry
- **Input**: Master password, service name
- **Output**: Decrypted entry dict or None if not found
- **Process**:
  1. Load vault
  2. Iterate entries, deobfuscate service names
  3. Match service_name
  4. Derive key, decrypt all fields
  5. Return plaintext entry
- **Error Handling**: Handle wrong master password, missing entry

##### `search_entries(master_password: str, keyword: str) -> list[dict]`
- **Purpose**: Search entries by keyword
- **Input**: Master password, search keyword
- **Output**: List of matching entries (decrypted)
- **Process**:
  1. Load vault
  2. For each entry: deobfuscate, decrypt
  3. Search in service_name, username, source_info
  4. Return matching entries
- **Error Handling**: Handle empty results, decryption errors

##### `update_entry(master_password: str, service_name: str, username: str = None, password: str = None, source_info: str = None) -> bool`
- **Purpose**: Update existing entry
- **Input**: Master password, service name, optional fields to update
- **Output**: True if successful
- **Process**:
  1. Get existing entry
  2. Update provided fields
  3. Re-encrypt with new salt (optional: keep same salt)
  4. Save vault
- **Error Handling**: Handle entry not found, validation errors

##### `delete_entry(master_password: str, service_name: str) -> bool`
- **Purpose**: Delete an entry
- **Input**: Master password, service name
- **Output**: True if successful
- **Process**:
  1. Load vault
  2. Find entry by deobfuscating keys
  3. Remove entry
  4. Save vault
- **Error Handling**: Handle entry not found

##### `export_vault(master_password: str, export_path: str, format: str = "json") -> bool`
- **Purpose**: Export vault to backup file
- **Input**: Master password, export path, format (json/csv)
- **Output**: True if successful
- **Process**:
  1. Load and decrypt all entries
  2. Format as JSON or CSV
  3. Write to export_path
- **Error Handling**: Handle file write errors, invalid format

##### `import_vault(master_password: str, import_path: str, format: str = "json", merge: bool = False) -> bool`
- **Purpose**: Import entries from backup
- **Input**: Master password, import path, format, merge flag
- **Output**: True if successful
- **Process**:
  1. Read import file
  2. Parse entries
  3. If merge=False: replace vault
  4. If merge=True: add entries, skip duplicates
  5. Encrypt and save
- **Error Handling**: Handle file read errors, invalid format, duplicate entries

##### `verify_master_password(master_password: str, config_path: str = "./config.json") -> bool`
- **Purpose**: Verify master password without decrypting vault
- **Input**: Master password, config path
- **Output**: True if correct
- **Process**:
  1. Load config.json
  2. Derive key from master_password
  3. Compare with stored hash (or attempt to decrypt test entry)
- **Error Handling**: Handle missing config, invalid hash

##### `change_master_password(old_password: str, new_password: str) -> bool`
- **Purpose**: Change master password and re-encrypt all entries
- **Input**: Old and new master passwords
- **Output**: True if successful
- **Process**:
  1. Verify old password
  2. Load all entries, decrypt with old password
  3. For each entry: generate new salt, encrypt with new password
  4. Update verification hash
  5. Save vault and config
- **Error Handling**: Handle wrong old password, encryption errors

### 2. utils/obfuscation.py - Service Name Obfuscation

#### Functions Specification

##### `obfuscate_service_name(service_name: str, salt: bytes) -> str`
- **Purpose**: Obfuscate service name for storage
- **Input**: Service name string, 16-byte salt
- **Output**: Base64-encoded obfuscated string
- **Process**:
  1. Convert service_name to bytes (UTF-8)
  2. Concatenate with salt
  3. Encode to base64
- **Error Handling**: Handle encoding errors

##### `deobfuscate_service_name(obfuscated_key: str, salt: bytes) -> str`
- **Purpose**: Recover original service name
- **Input**: Obfuscated key (base64), salt
- **Output**: Original service name
- **Process**:
  1. Decode base64 to bytes
  2. Remove last 16 bytes (salt)
  3. Decode remaining bytes to UTF-8
- **Error Handling**: Handle invalid base64, wrong salt size

##### `generate_salt() -> bytes`
- **Purpose**: Generate cryptographically secure random salt
- **Output**: 16-byte random salt
- **Implementation**: `secrets.token_bytes(16)`

### 3. utils/biometric.py - Biometric Authentication

#### Platform-Specific Implementation

##### Windows Hello
- **Library**: `windows.security.credentials.ui` (Windows API)
- **Process**:
  1. Request Windows Hello authentication
  2. On success, decrypt master password blob from storage
  3. Return decrypted master password (in memory only)
- **Storage**: Encrypted blob in `biometric.db`

##### macOS TouchID/Keychain
- **Library**: `LocalAuthentication` framework (via PyObjC or subprocess)
- **Process**:
  1. Use TouchID/FaceID authentication
  2. On success, retrieve encrypted master password from Keychain
  3. Decrypt using biometric key
  4. Return master password
- **Storage**: Keychain Services + encrypted blob

##### Linux
- **Fallback**: No default biometric support
- **Alternative**: Use system keyring (libsecret) for secure storage
- **Process**: Prompt for master password (no biometric)

##### Android (Future)
- **Library**: Android BiometricPrompt API (via Kivy)
- **Process**: Similar to other platforms

#### Functions Specification

##### `is_biometric_available(platform: str = None) -> bool`
- **Purpose**: Check if biometric authentication is available
- **Input**: Platform string (auto-detect if None)
- **Output**: True if available

##### `store_encrypted_master_password(master_password: str, platform: str) -> bool`
- **Purpose**: Encrypt and store master password for biometric unlock
- **Input**: Master password, platform
- **Output**: True if successful
- **Process**:
  1. Generate platform-specific encryption key
  2. Encrypt master password
  3. Store in biometric.db
  4. Store key in platform keychain (macOS/Windows)

##### `unlock_with_biometric(platform: str = None) -> str | None`
- **Purpose**: Authenticate with biometric and return master password
- **Input**: Platform (auto-detect)
- **Output**: Master password string or None if failed
- **Process**:
  1. Check biometric availability
  2. Request biometric authentication
  3. On success, retrieve and decrypt master password
  4. Return master password (caller responsible for memory cleanup)

##### `remove_biometric_storage(platform: str = None) -> bool`
- **Purpose**: Remove stored biometric data
- **Input**: Platform
- **Output**: True if successful

### 4. utils/cloud_sync.py - Proton Drive Synchronization

#### Functions Specification

##### `sync_to_proton_drive(vault_path: str, proton_path: str) -> bool`
- **Purpose**: Copy encrypted vault.json to Proton Drive folder
- **Input**: Vault file path, Proton Drive sync path
- **Output**: True if successful
- **Process**:
  1. Verify vault.json exists
  2. Verify Proton Drive path exists and is writable
  3. Copy vault.json to Proton Drive folder
  4. Optionally create timestamped backup
- **Error Handling**: Handle missing paths, permission errors, disk full

##### `sync_from_proton_drive(vault_path: str, proton_path: str, backup: bool = True) -> bool`
- **Purpose**: Copy vault.json from Proton Drive to local storage
- **Input**: Local vault path, Proton Drive path, backup flag
- **Output**: True if successful
- **Process**:
  1. Backup existing vault.json if backup=True
  2. Copy from Proton Drive to local
  3. Verify file integrity (optional: JSON validation)
- **Error Handling**: Handle missing source, file conflicts

##### `auto_sync_enabled() -> bool`
- **Purpose**: Check if auto-sync is enabled in config
- **Output**: True if enabled

##### `enable_auto_sync(proton_path: str) -> bool`
- **Purpose**: Enable automatic sync on vault save
- **Input**: Proton Drive path
- **Output**: True if successful

##### `disable_auto_sync() -> bool`
- **Purpose**: Disable automatic sync
- **Output**: True if successful

### 5. cli.py - Command Line Interface

#### Menu Structure
```
╔════════════════════════════════════╗
║   Secure Password Vault - CLI      ║
╠════════════════════════════════════╣
║  1. Add Entry                      ║
║  2. Get Entry                      ║
║  3. Search Entries                 ║
║  4. Update Entry                   ║
║  5. Delete Entry                   ║
║  6. Export Vault                   ║
║  7. Import Vault                   ║
║  8. Change Master Password         ║
║  9. Setup Biometric Unlock         ║
║ 10. Sync with Proton Drive         ║
║ 11. Quit                           ║
╚════════════════════════════════════╝
```

#### Functions Specification

##### `main() -> None`
- **Purpose**: Main CLI entry point
- **Process**:
  1. Check if vault exists (first run)
  2. If first run: setup wizard (create master password)
  3. Otherwise: prompt for master password (or biometric)
  4. Show menu, handle user input
  5. Loop until quit

##### `setup_wizard() -> str`
- **Purpose**: Initial setup for new users
- **Output**: Master password (for verification)
- **Process**:
  1. Welcome message
  2. Explain security model
  3. Prompt for master password (with getpass)
  4. Confirm master password
  5. Generate recovery phrase (optional)
  6. Create config.json
  7. Create empty vault.json

##### `prompt_master_password(allow_biometric: bool = True) -> str`
- **Purpose**: Get master password from user
- **Input**: Whether to allow biometric
- **Output**: Master password string
- **Process**:
  1. If biometric enabled and available: offer biometric unlock
  2. Otherwise: prompt with getpass
  3. Verify password
  4. Return password

##### `handle_add_entry(master_password: str) -> None`
- **Purpose**: CLI handler for adding entry
- **Process**:
  1. Prompt for service_name, username, password, source_info
  2. Use getpass for password input
  3. Call vault.add_entry()
  4. Show success/error message

##### `handle_get_entry(master_password: str) -> None`
- **Purpose**: CLI handler for getting entry
- **Process**:
  1. Prompt for service_name
  2. Call vault.get_entry()
  3. Display entry (mask password by default, option to show)
  4. Handle not found

##### `handle_search_entries(master_password: str) -> None`
- **Purpose**: CLI handler for searching
- **Process**:
  1. Prompt for keyword
  2. Call vault.search_entries()
  3. Display results in table format
  4. Handle empty results

### 6. gui_streamlit.py - Streamlit Desktop GUI

#### UI Components

##### Main App Structure
```python
# Sidebar: Navigation
- Home
- Add Entry
- View Entries
- Search
- Settings
- Export/Import

# Main Area: Dynamic content based on selection
```

##### Pages/Sections

1. **Home/Dashboard**
   - Welcome message
   - Vault statistics (entry count, last updated)
   - Quick actions
   - Master password prompt (if not authenticated)

2. **Add Entry**
   - Form with fields:
     - Service Name (text input)
     - Username (text input)
     - Password (text input, show/hide toggle)
     - Source Info (textarea)
   - Submit button
   - Success/error messages

3. **View Entries**
   - List of all entries (service names only)
   - Click to expand and view details
   - Copy to clipboard buttons
   - Edit/Delete actions

4. **Search**
   - Search input
   - Results table
   - Filter options

5. **Settings**
   - Change master password
   - Biometric setup
   - Proton Drive sync configuration
   - Export/Import options

#### Functions Specification

##### `main() -> None`
- **Purpose**: Streamlit app entry point
- **Process**:
  1. Initialize session state
  2. Check authentication
  3. Render sidebar navigation
  4. Route to appropriate page

##### `check_authentication() -> bool`
- **Purpose**: Check if user is authenticated
- **Output**: True if authenticated
- **Process**: Check session state for master_password

##### `authenticate_user() -> bool`
- **Purpose**: Authenticate user with master password or biometric
- **Output**: True if successful
- **Process**:
  1. Show password input or biometric button
  2. Verify master password
  3. Store in session state (temporary, cleared on logout)

### 7. gui_web.py - FastAPI Web Interface

#### API Routes

##### `GET /`
- **Purpose**: Serve main HTML page
- **Response**: HTML template

##### `POST /api/auth`
- **Purpose**: Authenticate user
- **Request**: `{"master_password": "..."}`
- **Response**: `{"success": true, "token": "session_token"}`
- **Security**: Use session tokens, store in memory (not persistent)

##### `GET /api/entries`
- **Purpose**: List all entries (service names only)
- **Headers**: `Authorization: Bearer <token>`
- **Response**: `{"entries": ["service1", "service2", ...]}`

##### `POST /api/entries`
- **Purpose**: Add new entry
- **Headers**: `Authorization: Bearer <token>`
- **Request**: `{"service_name": "...", "username": "...", "password": "...", "source_info": "..."}`
- **Response**: `{"success": true}`

##### `GET /api/entries/{service_name}`
- **Purpose**: Get specific entry
- **Headers**: `Authorization: Bearer <token>`
- **Response**: `{"service_name": "...", "username": "...", "password": "...", "source_info": "..."}`

##### `PUT /api/entries/{service_name}`
- **Purpose**: Update entry
- **Headers**: `Authorization: Bearer <token>`
- **Request**: Partial update fields
- **Response**: `{"success": true}`

##### `DELETE /api/entries/{service_name}`
- **Purpose**: Delete entry
- **Headers**: `Authorization: Bearer <token>`
- **Response**: `{"success": true}`

##### `GET /api/search?q={keyword}`
- **Purpose**: Search entries
- **Headers**: `Authorization: Bearer <token>`
- **Response**: `{"results": [...]}`

##### `POST /api/export`
- **Purpose**: Export vault
- **Headers**: `Authorization: Bearer <token>`
- **Response**: File download (JSON)

##### `POST /api/import`
- **Purpose**: Import vault
- **Headers**: `Authorization: Bearer <token>`
- **Request**: Multipart file upload
- **Response**: `{"success": true, "imported": 5}`

#### HTML Templates

##### Base Template (base.html)
- Modern, responsive design
- No external CDN (all CSS/JS inline or local)
- Dark theme option
- Navigation bar
- Footer

##### Home Page (index.html)
- Login form (master password)
- Dashboard after login
- Quick stats

##### Entries Page (entries.html)
- Entry list/table
- Add entry form
- View/edit modals

##### Search Page (search.html)
- Search input
- Results display

#### Security Considerations
- Session tokens expire after inactivity
- HTTPS recommended (self-signed cert for local)
- Rate limiting on auth endpoints
- CSRF protection
- Input validation and sanitization

---

## 🎨 User Interfaces

### CLI Interface Design

#### Color Scheme
- Success: Green
- Error: Red
- Warning: Yellow
- Info: Cyan
- Use `colorama` or `rich` library for colors

#### Input Validation
- Service name: Non-empty, max 100 chars
- Username: Non-empty, max 255 chars
- Password: Non-empty, no length limit
- Source info: Optional, max 1000 chars

#### Output Formatting
- Tables for entry lists (use `tabulate` or `rich.table`)
- Masked passwords by default (`****`)
- Option to show password: `--show-password` flag

### Streamlit GUI Design

#### Theme
- Dark mode default
- Clean, modern UI
- Responsive layout
- Icons for actions (using emoji or streamlit components)

#### User Experience
- Password strength indicator
- Copy-to-clipboard buttons
- Confirmation dialogs for destructive actions
- Loading indicators for long operations
- Toast notifications for success/error

### Web UI Design

#### Design Principles
- Mobile-responsive
- Accessible (WCAG 2.1 AA)
- Fast loading (minimal dependencies)
- Progressive enhancement

#### Components
- Login page with master password input
- Dashboard with entry cards
- Modal dialogs for add/edit
- Search bar with live results
- Settings page with tabs

---

## ⚠️ Error Handling & Edge Cases

### Error Categories

#### 1. Authentication Errors
- **Wrong master password**: Clear error message, allow retry
- **Biometric failure**: Fallback to password prompt
- **Session expired**: Redirect to login

#### 2. File System Errors
- **Vault file not found**: Treat as first run, show setup wizard
- **Permission denied**: Clear error, suggest running with correct permissions
- **Disk full**: Error message, suggest cleanup
- **File corruption**: Attempt recovery, offer backup restore

#### 3. Encryption Errors
- **Decryption failure**: Wrong master password or corrupted data
- **Invalid salt**: Data corruption, suggest restore from backup
- **Key derivation failure**: Invalid parameters, log error

#### 4. Data Validation Errors
- **Empty fields**: Validate before encryption
- **Invalid JSON**: Handle gracefully, offer repair
- **Duplicate service names**: Warn user, offer to update or rename

#### 5. Network/Sync Errors
- **Proton Drive path not found**: Clear error, check configuration
- **Sync conflict**: Detect and handle (timestamp-based resolution)
- **Connection timeout**: Retry mechanism

### Edge Cases

#### 1. First Run
- No vault.json exists
- Show setup wizard
- Create initial config.json
- Initialize empty vault.json

#### 2. Empty Vault
- Handle gracefully in all UIs
- Show "No entries" message
- Disable search/export if empty

#### 3. Very Large Vaults
- Optimize loading (lazy loading for GUI)
- Pagination for entry lists
- Streaming for export/import

#### 4. Concurrent Access
- File locking mechanism
- Detect concurrent modifications
- Warn user about conflicts

#### 5. Master Password Change Interruption
- Atomic operation: all or nothing
- Backup before change
- Rollback on failure

#### 6. Biometric Unavailable
- Graceful fallback to password
- Clear messaging to user
- Option to disable biometric

#### 7. Invalid/Corrupted vault.json
- JSON validation on load
- Attempt to repair (if possible)
- Offer restore from backup
- Last resort: start fresh (with warning)

---

## 📦 Dependencies & Configuration

### Dependency Management

#### Choice: Poetry (Recommended)
- Better dependency resolution
- Virtual environment management
- Lock file for reproducible builds
- Easy publishing (if needed)

#### Python Version
- **Requirement**: Python < 3.12 (use 3.11 or 3.10)
- **Recommended**: Python 3.11 (best balance of features and stability)

#### Core Dependencies

##### Required
```toml
[tool.poetry.dependencies]
python = "^3.10,<3.12"
cryptography = "^41.0.0"  # Fernet encryption
fastapi = "^0.104.0"      # Web framework
uvicorn = "^0.24.0"        # ASGI server
streamlit = "^1.28.0"      # Streamlit GUI
pydantic = "^2.5.0"        # Data validation
python-dotenv = "^1.0.0"   # Environment variables
```

##### Optional (Platform-Specific)
```toml
[tool.poetry.dependencies]
# Windows
pywin32 = {version = "^306", markers = "sys_platform == 'win32'"}
# macOS
pyobjc = {version = "^10.0", markers = "sys_platform == 'darwin'"}
# Linux
secretstorage = {version = "^3.3", markers = "sys_platform == 'linux'"}
```

##### Development
```toml
[tool.poetry.group.dev.dependencies]
pytest = "^7.4.0"
pytest-cov = "^4.1.0"
black = "^23.11.0"
mypy = "^1.7.0"
ruff = "^0.1.6"
```

### Configuration Management

#### Environment Variables
- `VAULT_PATH`: Override default vault.json path
- `CONFIG_PATH`: Override default config.json path
- `PROTON_DRIVE_PATH`: Proton Drive sync path
- `LOG_LEVEL`: Logging level (DEBUG, INFO, WARNING, ERROR)

#### Config File (config.json)
- Master password verification hash
- PBKDF2 iterations (configurable, min 200k)
- Proton Drive sync settings
- Biometric settings
- UI preferences (theme, etc.)

---

## 🧪 Testing Strategy

### Test Categories

#### 1. Unit Tests
- **vault.py**: Test each function in isolation
  - Key derivation
  - Encryption/decryption
  - Vault CRUD operations
  - Import/export
- **obfuscation.py**: Test obfuscation/deobfuscation
- **biometric.py**: Mock platform-specific APIs
- **cloud_sync.py**: Test file operations

#### 2. Integration Tests
- End-to-end vault operations
- Master password change flow
- Import/export workflows
- Biometric unlock flow

#### 3. Security Tests
- Verify no password logging
- Verify no plaintext storage
- Test with wrong master password
- Test with corrupted data
- Test salt uniqueness

#### 4. Performance Tests
- Large vault handling (1000+ entries)
- Encryption/decryption speed
- File I/O performance

#### 5. UI Tests
- CLI menu navigation
- Streamlit page routing
- Web API endpoints

### Test Data
- Use test fixtures for consistent testing
- Mock file system operations
- Use deterministic salts for some tests
- Test with various entry sizes

---

## 🚀 Deployment & Usage

### Installation Instructions

#### Prerequisites
- Python 3.10 or 3.11
- Poetry (or uv) installed
- Git (for cloning)

#### Setup Steps
```bash
# 1. Clone repository
git clone <repo-url>
cd SecureSensitiveDataEncrypt

# 2. Install dependencies
poetry install
# OR
uv pip install -r requirements.txt

# 3. Run setup (first time)
poetry run python cli.py
# Follow setup wizard

# 4. Run application
# CLI:
poetry run python cli.py

# Streamlit GUI:
poetry run streamlit run gui_streamlit.py

# Web UI:
poetry run python gui_web.py
# Access at http://localhost:8000
```

### Running the Application

#### CLI Mode
```bash
python cli.py
```

#### Streamlit GUI
```bash
streamlit run gui_streamlit.py
```

#### Web UI
```bash
python gui_web.py
# Or with uvicorn:
uvicorn gui_web:app --host 127.0.0.1 --port 8000
```

### Proton Drive Sync Setup

#### Prerequisites
1. Install Proton Drive desktop app
2. Set up local sync folder
3. Note the sync folder path

#### Configuration
1. Open application settings
2. Navigate to "Cloud Sync" section
3. Enter Proton Drive sync folder path
4. Test sync (manual sync first)
5. Enable auto-sync if desired

#### Manual Sync
- Use CLI: Option 10 in menu
- Use GUI: Settings → Sync Now
- Use Web UI: Settings → Sync button

#### Auto-Sync
- Enabled in settings
- Automatically syncs after each vault save
- Background process (non-blocking)

### Biometric Unlock Setup

#### macOS
1. Ensure TouchID/FaceID is set up on Mac
2. In app settings, enable "Biometric Unlock"
3. Enter master password to encrypt and store
4. Future unlocks use TouchID/FaceID

#### Windows
1. Ensure Windows Hello is configured
2. Enable biometric unlock in settings
3. Authenticate with Windows Hello
4. Store encrypted master password

#### Linux
- No default biometric support
