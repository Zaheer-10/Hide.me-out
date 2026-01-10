# Secure Sensitive Data Encrypt

A secure, local-first password vault with strong cryptography and multiple UIs (Web, Streamlit, Tkinter) plus a JSON API. Now with **S3 cloud sync** support.

## Features
- AES‑256‑GCM for entry encryption bound to an app instance
- FastAPI JSON API with CSRF and rate limiting
- Server-rendered Web UI with responsive, professional styling
- Streamlit and Tkinter desktop UIs
- Audit logging with restricted file permissions
- Poetry-managed dependencies and tests
- **S3 Cloud Sync**: Automatic vault synchronization to AWS S3
- **Master Password Hint**: Encrypted hints stored in S3 for password recovery assistance

## Architecture
- Core: `vault/` implements the vault engine and configuration
  - `vault/vault.py`: entry CRUD and import/export
  - `vault/config.py`: security policy, config storage, audit logging, instance materials
  - `vault/utils/aes.py`: key derivation and AES‑GCM helpers
- Web/API: `vault/gui_web.py` exposes HTML pages and `/api/*` endpoints
- Desktop UIs: `vault/gui_streamlit.py`, `vault/gui_tkinter.py`
- Storage: `vault/storage/*` holds local config, audit log, and instance secret

## Getting Started
### Prerequisites
- Python 3.11 recommended (>=3.10,<3.12 supported)
- Install with Poetry:

```bash
pip install poetry
poetry install --only main
```

### Run the Web UI
```bash
poetry run uvicorn vault.gui_web:app --host 0.0.0.0 --port 8000
```
- Open `http://localhost:8000`
- API docs: `http://localhost:8000/docs` (Swagger) and `http://localhost:8000/redoc`

### Streamlit UI
```bash
poetry run streamlit run vault/gui_streamlit.py
```

### Tkinter UI
```bash
poetry run python -m vault.gui_tkinter
```

## API Overview

### Authentication
- `GET /api/auth/csrf-token` – issue CSRF token
- `POST /api/auth/setup-master` – configure master password (with optional hint)
- `GET /api/auth/hint` – get master password hint
- `POST /api/auth/hint` – set/update master password hint

### Passwords
- `POST /api/passwords/encrypt` – encrypt a password entry
- `POST /api/passwords/decrypt` – decrypt an entry (requires master)
- `POST /api/passwords/update` – update an entry's password (requires master)

### S3 Sync
- `GET /api/s3/status` – get S3 configuration and sync status
- `POST /api/s3/sync-to` – upload local vault to S3
- `POST /api/s3/sync-from` – download vault from S3

Headers
- `X-CSRF-Token: <token from /api/auth/csrf-token>`
- HTTPS enforcement can be enabled via config

## Configuration & Storage
- Config: `vault/storage/config.json` (auto-created with safe defaults)
- Instance secret: `vault/storage/instance.secret` (0o600)
- Audit log: `vault/storage/audit.log` (0o600)
- Vault data: `vault/storage/vault.json`

These paths are ignored by Git via `.gitignore` to avoid committing local state.

## S3 Cloud Sync Configuration

The vault supports automatic synchronization to AWS S3. Set the following environment variables:

```bash
# Required
export AWS_ACCESS_KEY_ID=your_access_key_id
export AWS_SECRET_ACCESS_KEY=your_secret_access_key
export S3_BUCKET_NAME=your-bucket-name
export AWS_REGION=ap-south-2

# Optional (defaults to "vault/")
export S3_VAULT_PATH=vault/
```

### S3 Features
- **Auto-sync**: When enabled, vault changes are automatically uploaded to S3
- **Load from S3**: On startup, if local vault is missing, downloads from S3
- **Manual sync**: Use the S3 Sync page in the Web UI or API endpoints
- **Password hints**: Encrypted hints stored in S3 for password recovery assistance

### S3 API Endpoints
- `GET /api/s3/status` – Get S3 configuration and sync status
- `POST /api/s3/sync-to` – Upload local vault to S3
- `POST /api/s3/sync-from` – Download vault from S3 to local
- `GET /api/auth/hint` – Get master password hint
- `POST /api/auth/hint` – Set master password hint

### Security Notes for S3
- S3 objects use server-side encryption (SSE-S3)
- Password hints are encrypted with the instance secret before upload
- AWS credentials should be stored in environment variables, never in code
- Use IAM roles with minimal permissions (s3:GetObject, s3:PutObject, s3:DeleteObject on specific bucket/prefix)

## Deployment
GitHub Pages hosts static sites only and cannot run the FastAPI backend. Use a free platform that supports Python web services:

### Option 1: Render (free tier)
- Add `render.yaml` and `Dockerfile` (included in this repo)
- Create a new Web Service on Render, connect the repo, set port `8000`
- Health check path: `/`

### Option 2: Railway/Fly.io
- Use the provided `Dockerfile`
- Configure service to run `uvicorn vault.gui_web:app --host 0.0.0.0 --port 8000`

## CI/CD
GitHub Actions runs tests on each push/PR. A deploy workflow can be added to call the hosting provider API; store credentials as repository secrets.

## Security Notes
- Never commit secrets or local storage files; `.gitignore` prevents this
- Master password hash is stored in config; verification uses bcrypt
- Audit logs exclude secrets by design

## License
MIT