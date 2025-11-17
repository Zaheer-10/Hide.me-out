# Secure Sensitive Data Encrypt

A secure, local-first password vault with strong cryptography and multiple UIs (Web, Streamlit, Tkinter) plus a JSON API.

## Features
- AES‑256‑GCM for entry encryption bound to an app instance
- FastAPI JSON API with CSRF and rate limiting
- Server-rendered Web UI with responsive, professional styling
- Streamlit and Tkinter desktop UIs
- Audit logging with restricted file permissions
- Poetry-managed dependencies and tests

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
- `GET /api/auth/csrf-token` – issue CSRF token
- `POST /api/auth/setup-master` – configure master password
- `POST /api/passwords/encrypt` – encrypt a password entry
- `POST /api/passwords/decrypt` – decrypt an entry (requires master)
- `POST /api/passwords/update` – update an entry’s password (requires master)

Headers
- `X-CSRF-Token: <token from /api/auth/csrf-token>`
- HTTPS enforcement can be enabled via config

## Configuration & Storage
- Config: `vault/storage/config.json` (auto-created with safe defaults)
- Instance secret: `vault/storage/instance.secret` (0o600)
- Audit log: `vault/storage/audit.log` (0o600)
- Vault data: `vault/storage/vault.json`

These paths are ignored by Git via `.gitignore` to avoid committing local state.

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