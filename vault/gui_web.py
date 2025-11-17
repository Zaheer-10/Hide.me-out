"""FastAPI Web UI and JSON API for the secure vault.

Local-only server with inline templates. No external CDNs.
Adds JSON API endpoints for master setup and AES-256 password encryption/decryption.
"""

# pyright: reportMissingImports=false, reportMissingTypeStubs=false
# mypy: ignore-missing-imports

from __future__ import annotations

import os
from fastapi import (
    FastAPI,
    Form,
    Request,
    Depends,
    Header,
    HTTPException,
    UploadFile,
    File,
)
from fastapi import status
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field
from fastapi.staticfiles import StaticFiles
from jinja2 import Template
from starlette.middleware.sessions import SessionMiddleware
from time import time

from .vault import add_entry, get_entry, search_entries
from .vault import update_entry
from .config import (
    ensure_instance_materials,
    get_instance_secret,
    get_app_salt,
    get_csrf_secret,
    get_master_password_hash,
    set_master_password_hash,
    clear_master_password_hash,
    load_config,
)
from .utils.aes import derive_aes_key, aes_gcm_encrypt, aes_gcm_decrypt

# bcrypt is used for master password hashing/verification
import bcrypt  # type: ignore


app = FastAPI()

# Serve static assets (favicon)
try:
    static_dir = os.path.join(os.path.dirname(__file__), "static")
    if os.path.isdir(static_dir):
        app.mount("/static", StaticFiles(directory=static_dir), name="static")
except Exception:
    pass


# Secure session management (strict same-site, optional HTTPS-only)
try:
    ensure_instance_materials()
    token = get_csrf_secret()
    cfg_mid = load_config()
    https_only = bool(cfg_mid.get("enforce_https", False))
    app.add_middleware(
        SessionMiddleware, secret_key=token, same_site="strict", https_only=https_only
    )
except Exception:
    # Continue without sessions if initialization fails
    pass


BASE_TEMPLATE = Template(
    """
    <!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="utf-8" />
      <meta name="viewport" content="width=device-width, initial-scale=1" />
      <title>Hide.me-out</title>
      <link rel="icon" href="/static/favicon.svg" type="image/svg+xml" />
      <style>
        :root {
          --bg: #0a0f0a;
          --text: #c8f7dc;
          --muted: #7fbf9b;
          --surface: #0d1510;
          --border: #163522;
          --primary: #00f39f;
          --primary-700: #00d48d;
          --shadow: 0 8px 28px rgba(0, 255, 153, 0.08);
        }
        @keyframes glow { from { text-shadow: 0 0 2px rgba(0,243,159,0.6); } to { text-shadow: 0 0 8px rgba(0,243,159,0.9); } }
        @keyframes gridMove { from { background-position: 0 0, 0 0; } to { background-position: 100px 100px, -100px 50px; } }
        body { background-image: radial-gradient(circle at 20% 10%, rgba(0,243,159,0.06), transparent 60%),
                             radial-gradient(circle at 80% 40%, rgba(0,243,159,0.04), transparent 60%);
               animation: gridMove 18s linear infinite; }
        * { box-sizing: border-box; }
        html, body { height: 100%; }
        body { margin: 0; font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", monospace; background: var(--bg); color: var(--text); }
        .container { width: 100%; max-width: 960px; margin: 0 auto; padding: 24px; }
        header { position: sticky; top: 0; backdrop-filter: saturate(180%) blur(8px); background: color-mix(in oklab, var(--surface) 92%, transparent); border-bottom: 1px solid var(--border); z-index: 20; }
        .nav { display: flex; align-items: center; justify-content: space-between; gap: 16px; padding: 12px 24px; }
        .brand { font-weight: 800; letter-spacing: 0.6px; color: var(--primary); animation: glow 2.4s ease-in-out infinite alternate; }
        .links { display: flex; flex-wrap: wrap; gap: 10px; }
        .links a { text-decoration: none; color: var(--muted); padding: 8px 12px; border-radius: 8px; border: 1px solid transparent; }
        .links a:hover { color: var(--primary); border-color: var(--primary); }
        main { padding-top: 6px; }
        h1, h2, h3 { margin: 0 0 10px; }
        .grid { display: grid; grid-template-columns: 1fr; gap: 16px; }
        @media (min-width: 768px) { .grid-2 { grid-template-columns: 1fr 1fr; } }
        .card { background: linear-gradient(180deg, #0e1712, #0b120e); border: 1px solid var(--border); border-radius: 16px; padding: 18px; box-shadow: var(--shadow); }
        form { display: grid; gap: 12px; }
        .form-grid { display: grid; grid-template-columns: 1fr; gap: 12px; }
        @media (min-width: 768px) { .form-grid { grid-template-columns: 1fr 1fr; } }
        label { font-size: 0.92rem; color: var(--muted); }
        input, textarea { width: 100%; padding: 10px 12px; border-radius: 10px; border: 1px solid var(--border); background: #0a140f; color: var(--text); }
        input:focus, textarea:focus { outline: none; border-color: var(--primary); box-shadow: 0 0 0 4px color-mix(in oklab, var(--primary) 20%, transparent); }
        .actions { display: flex; gap: 10px; justify-content: flex-end; }
        .btn { appearance: none; border: 1px solid var(--border); background: #0a140f; color: var(--text); padding: 10px 16px; border-radius: 10px; cursor: pointer; font-weight: 600; }
        .btn:hover { border-color: var(--primary); color: var(--primary); }
        .btn.primary { background: var(--primary); color: #052018; border-color: var(--primary); }
        .btn.primary:hover { background: var(--primary-700); border-color: var(--primary-700); }
        .hint { font-size: 0.85rem; color: var(--muted); }
        .entry { display: grid; gap: 6px; }
        .entry strong { color: var(--primary); }
        .field { display: grid; gap: 6px; }
        .input-row { display: flex; gap: 8px; align-items: center; }
        .btn.eye { padding: 6px 10px; font-size: 0.9rem; }
      </style>
    </head>
    <body>
      <header>
        <div class="nav">
          <div class="brand">Hide.me-out</div>
          <nav class="links">
            <a href="/">Home</a>
            <a href="/add">Create</a>
            <a href="/get">Get</a>
            <a href="/update">Update</a>
            <a href="/delete">Delete</a>
            <a href="/search">Search</a>
            <a href="/encrypt">Encrypt</a>
            <a href="/decrypt">Decrypt</a>
            <a href="/services">Services</a>
            <a href="/export">Export</a>
            <a href="/import">Import</a>
            <a href="/dashboard">Dashboard</a>
            <a href="/master">Master</a>
            <a href="/reset">Reset</a>
          </nav>
        </div>
      </header>
      <main>
        <div class="container">
          {{ content | safe }}
        </div>
      </main>
    </body>
    </html>
    """
)


# ------------------------- Security Dependencies -------------------------


def _enforce_https(request: Request) -> None:
    cfg = load_config()
    if not cfg.get("enforce_https", False):
        return
    scheme = request.url.scheme
    xf_proto = request.headers.get("x-forwarded-proto", "").lower()
    if scheme != "https" and xf_proto != "https":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={
                "success": False,
                "code": "https_required",
                "message": "HTTPS is required for this endpoint",
                "error": "Sensitive operations must be performed over HTTPS",
            },
        )


def require_csrf(x_csrf_token: str = Header(default="")) -> None:
    secret_b64 = get_csrf_secret()
    if not secret_b64:
        # Initialize instance materials on first run
        ensure_instance_materials()
        secret_b64 = get_csrf_secret()
    if not x_csrf_token or x_csrf_token != secret_b64:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={
                "success": False,
                "code": "csrf_invalid",
                "message": "Invalid CSRF token",
                "error": "Provide valid X-CSRF-Token header",
            },
        )


# ----------------------------- Rate Limiting ------------------------------
# In-memory rate limiter store: IP -> timestamps within window
_rl_store: dict[str, list[float]] = {}


def rate_limit(key: str, window_sec: int, max_attempts: int) -> None:
    now = time()
    bucket = _rl_store.get(key, [])
    bucket = [t for t in bucket if now - t < window_sec]
    if len(bucket) >= max_attempts:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail={
                "success": False,
                "code": "rate_limited",
                "message": "Too many attempts",
                "error": f"Max {max_attempts} within {window_sec}s",
            },
        )
    bucket.append(now)
    _rl_store[key] = bucket


# ------------------------------ API Models --------------------------------


class StandardResponse(BaseModel):
    success: bool
    code: str
    message: str
    error: str | None = None
    data: dict | None = None
    model_config = dict(
        json_schema_extra={
            "example": {
                "success": True,
                "code": "encrypted",
                "message": "Password entry encrypted",
                "data": {
                    "encrypted_key": "b64...",
                    "nonce_b64": "b64...",
                    "algorithm": "AES-256-GCM",
                },
            }
        }
    )


class SetupMasterRequest(BaseModel):
    password: str = Field(..., min_length=12)
    confirm: str = Field(..., min_length=12)
    masked: bool = Field(True, description="Client-side mask/unmask preference")
    model_config = dict(
        json_schema_extra={
            "example": {
                "password": "Str0ng!MasterPass",
                "confirm": "Str0ng!MasterPass",
                "masked": True,
            }
        }
    )


class EncryptRequest(BaseModel):
    service_name: str = Field(..., min_length=1)
    username: str = Field(..., min_length=1)
    password: str = Field(..., min_length=1)
    model_config = dict(
        json_schema_extra={
            "example": {
                "service_name": "github",
                "username": "alice",
                "password": "Sup3r$ecret!",
            }
        }
    )


class DecryptRequest(BaseModel):
    encrypted_key: str
    nonce_b64: str
    master_password: str = Field(..., min_length=12)
    model_config = dict(
        json_schema_extra={
            "example": {
                "encrypted_key": "b64 ciphertext",
                "nonce_b64": "b64 nonce",
                "master_password": "Str0ng!MasterPass",
            }
        }
    )


class UpdateRequest(BaseModel):
    service_name: str = Field(..., min_length=1)
    new_password: str = Field(..., min_length=12)
    master_password: str = Field(..., min_length=12)
    model_config = dict(
        json_schema_extra={
            "example": {
                "service_name": "github",
                "new_password": "N3w$uperSecret!",
                "master_password": "Str0ng!MasterPass",
            }
        }
    )


def is_strong_password(pw: str) -> bool:
    """Basic strength: >=12 chars, upper/lower/digit/special."""
    if not isinstance(pw, str) or len(pw) < 12:
        return False
    has_upper = any(c.isupper() for c in pw)
    has_lower = any(c.islower() for c in pw)
    has_digit = any(c.isdigit() for c in pw)
    has_special = any(not c.isalnum() for c in pw)
    return has_upper and has_lower and has_digit and has_special


# ----------------------------- API Endpoints ------------------------------


@app.get(
    "/api/auth/csrf-token",
    summary="Issue CSRF token",
    description="Returns an application-bound CSRF token to be sent as X-CSRF-Token on sensitive API requests.",
    tags=["Auth"],
    response_model=StandardResponse,
)
def get_csrf_token(_: Request):
    ensure_instance_materials()
    return StandardResponse(
        success=True,
        code="csrf_token",
        message="CSRF token issued",
        data={"csrf_token": get_csrf_secret()},
    )


@app.post(
    "/api/auth/setup-master",
    summary="Configure master password",
    description="Sets the master password once using bcrypt with a high work factor. Requires HTTPS if enforced, and a valid CSRF token.",
    tags=["Auth"],
    response_model=StandardResponse,
)
def setup_master(
    req: SetupMasterRequest,
    request: Request,
    _https: None = Depends(_enforce_https),
    _csrf: None = Depends(require_csrf),
):
    # Validate confirmation
    if req.password != req.confirm:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "success": False,
                "code": "password_mismatch",
                "message": "Passwords do not match",
                "error": "Provide identical password and confirmation",
            },
        )

    # Strength validation
    pwd = req.password
    strong = (
        len(pwd) >= 12
        and any(c.islower() for c in pwd)
        and any(c.isupper() for c in pwd)
        and any(c.isdigit() for c in pwd)
        and any(c in "!@#$%^&*()_-+=[]{}:;,.?/" for c in pwd)
    )
    if not strong:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "success": False,
                "code": "weak_password",
                "message": "Password does not meet strength requirements",
                "error": "Min 12 chars with upper, lower, digit, symbol",
            },
        )

    # Ensure master is only set once
    if get_master_password_hash():
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={
                "success": False,
                "code": "master_exists",
                "message": "Master password already set",
                "error": "Reset not supported via this endpoint",
            },
        )

    # Hash and store with high work factor
    cfg = load_config()
    rounds = int(cfg.get("bcrypt_rounds", 14))
    salt = bcrypt.gensalt(rounds)
    hash_str = bcrypt.hashpw(req.password.encode("utf-8"), salt).decode("utf-8")
    set_master_password_hash(hash_str)

    return StandardResponse(
        success=True,
        code="master_setup",
        message="Master password configured",
        data={"masked": req.masked},
    )


@app.post(
    "/api/passwords/encrypt",
    summary="Encrypt a password entry",
    description="Encrypts service, username, and password into an AES‑256‑GCM payload bound to the application instance.",
    tags=["Passwords"],
    response_model=StandardResponse,
)
def api_encrypt(
    req: EncryptRequest,
    request: Request,
    _https: None = Depends(_enforce_https),
    _csrf: None = Depends(require_csrf),
):
    # Validate master exists
    if not get_master_password_hash():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "success": False,
                "code": "master_missing",
                "message": "Master password not configured",
                "error": "Call /api/auth/setup-master first",
            },
        )

    # Input validation already handled by Pydantic; add basic sanitation
    service = req.service_name.strip()
    username = req.username.strip()
    password = req.password
    if not service or not username or not password:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "success": False,
                "code": "invalid_input",
                "message": "Missing required fields",
                "error": "service_name, username, password are required",
            },
        )

    # Bind encryption to application instance
    ensure_instance_materials()
    instance_secret = get_instance_secret()
    app_salt = get_app_salt()
    cfg = load_config()
    aad = cfg.get("app_instance_id", "").encode("utf-8")
    key = derive_aes_key(instance_secret, app_salt)

    # Encrypt a compact JSON payload
    import json as _json

    payload = _json.dumps(
        {
            "service_name": service,
            "username": username,
            "password": password,
        },
        separators=(",", ":"),
    ).encode("utf-8")

    nonce_b64, encrypted_b64 = aes_gcm_encrypt(key, payload, aad=aad)

    return StandardResponse(
        success=True,
        code="encrypted",
        message="Password entry encrypted",
        data={
            "encrypted_key": encrypted_b64,
            "nonce_b64": nonce_b64,
            "algorithm": "AES-256-GCM",
        },
    )


@app.post(
    "/api/passwords/decrypt",
    summary="Decrypt an entry",
    description="Decrypts an AES‑256‑GCM payload when the provided master password matches the stored hash.",
    tags=["Passwords"],
    response_model=StandardResponse,
)
def api_decrypt(
    req: DecryptRequest,
    request: Request,
    _https: None = Depends(_enforce_https),
    _csrf: None = Depends(require_csrf),
):
    # Rate limit to prevent brute force
    cfg = load_config()
    window = int(cfg.get("rate_limit_window_sec", 60))
    max_attempts = int(cfg.get("rate_limit_max", 5))
    # Safely derive client identifier for rate limit
    client_host = ""
    client = getattr(request, "client", None)
    if client is not None:
        # request.client may be None; guard attribute access
        try:
            client_host = getattr(client, "host", "") or ""
        except Exception:
            client_host = ""
    xf = request.headers.get("x-forwarded-for", "")
    forwarded_ip = xf.split(",")[0].strip() if xf else ""
    ip_key = client_host or forwarded_ip or "unknown"
    key_rl = f"dec:{ip_key}"
    rate_limit(key_rl, window, max_attempts)

    # Validate master password against stored hash
    stored = get_master_password_hash()
    if not stored:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "success": False,
                "code": "master_missing",
                "message": "Master password not configured",
                "error": "Call /api/auth/setup-master first",
            },
        )
    try:
        ok = bcrypt.checkpw(req.master_password.encode("utf-8"), stored.encode("utf-8"))
    except Exception:
        ok = False
    if not ok:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={
                "success": False,
                "code": "auth_failed",
                "message": "Master password invalid",
                "error": "Authentication required",
            },
        )

    # Decrypt with application-bound key
    ensure_instance_materials()
    instance_secret = get_instance_secret()
    app_salt = get_app_salt()
    aad = cfg.get("app_instance_id", "").encode("utf-8")
    key = derive_aes_key(instance_secret, app_salt)

    try:
        pt = aes_gcm_decrypt(key, req.nonce_b64, req.encrypted_key, aad=aad)
        import json as _json

        data = _json.loads(pt.decode("utf-8"))
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "success": False,
                "code": "decrypt_failed",
                "message": "Failed to decrypt payload",
                "error": "Ciphertext invalid or mismatched instance",
            },
        )

    return StandardResponse(
        success=True,
        code="decrypted",
        message="Password entry decrypted",
        data=data,
    )


@app.post(
    "/api/passwords/update",
    summary="Update a password",
    description="Updates the stored password for a service after verifying the master password and input strength.",
    tags=["Passwords"],
    response_model=StandardResponse,
)
def api_update(
    req: UpdateRequest,
    request: Request,
    _https: None = Depends(_enforce_https),
    _csrf: None = Depends(require_csrf),
):
    # Rate limit update attempts
    cfg = load_config()
    window = int(cfg.get("rate_limit_window_sec", 60))
    max_attempts = int(cfg.get("rate_limit_max", 5))
    client_host = ""
    client = getattr(request, "client", None)
    if client is not None:
        try:
            client_host = getattr(client, "host", "") or ""
        except Exception:
            client_host = ""
    xf = request.headers.get("x-forwarded-for", "")
    forwarded_ip = xf.split(",")[0].strip() if xf else ""
    ip_key = client_host or forwarded_ip or "unknown"
    key_rl = f"upd:{ip_key}"
    rate_limit(key_rl, window, max_attempts)

    stored = get_master_password_hash()
    if not stored:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "success": False,
                "code": "master_missing",
                "message": "Master password not configured",
                "error": "Call /api/auth/setup-master first",
            },
        )
    try:
        ok_master = bcrypt.checkpw(
            req.master_password.encode("utf-8"), stored.encode("utf-8")
        )
    except Exception:
        ok_master = False
    if not ok_master:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={
                "success": False,
                "code": "auth_failed",
                "message": "Master password invalid",
                "error": "Authentication required",
            },
        )

    service = req.service_name.strip()
    if not service:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "success": False,
                "code": "invalid_input",
                "message": "service_name is required",
                "error": "Provide service_name",
            },
        )
    if not is_strong_password(req.new_password):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "success": False,
                "code": "weak_password",
                "message": "New password does not meet strength requirements",
                "error": "Min 12 chars with upper/lower/digit/special",
            },
        )

    try:
        ok = update_entry(req.master_password, service, password=req.new_password)
    except Exception:
        ok = False
    if not ok:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={
                "success": False,
                "code": "not_found",
                "message": "Service not found or update failed",
                "error": "Verify service_name exists",
            },
        )

    return StandardResponse(
        success=True,
        code="updated",
        message="Password updated successfully",
        data={"service_name": service},
    )


@app.get("/", response_class=HTMLResponse)
def home() -> HTMLResponse:
    content = """
    <div class="card">
      <h3>Welcome</h3>
      <p>Secure, local-only vault with multi-UI and strong encryption.</p>
      <div class="actions">
        <a href="/add" class="btn primary">Create Password</a>
        <a href="/search" class="btn">Search</a>
      </div>
    </div>
    """
    return HTMLResponse(BASE_TEMPLATE.render(content=content))


@app.get("/dashboard", response_class=HTMLResponse)
def dashboard() -> HTMLResponse:
    from .config import load_config
    from .vault import count_entries

    cfg = load_config()
    entries = count_entries()
    master_hash = cfg.get("master_password_hash")
    master_set_count = cfg.get("master_set_count")
    rotations_count = cfg.get("rotations_count")
    entries_display = entries if master_hash else 0
    content = f"""
    <div class=\"grid grid-2\">
      <div class=\"card\">
        <h3>Master Status</h3>
        <div>Configured: {"Yes" if master_hash else "No"}</div>
        {f"<div>Master set count: {master_set_count}</div>" if master_set_count is not None else ""}
        {f"<div>Rotations: {rotations_count}</div>" if rotations_count is not None else ""}
      </div>
      <div class=\"card\">
        <h3>Passwords</h3>
        <div>Total entries: {entries_display}</div>
      </div>
    </div>
    """
    return HTMLResponse(BASE_TEMPLATE.render(content=content))


@app.get("/services", response_class=HTMLResponse)
def services_get() -> HTMLResponse:
    from .vault import load_vault

    v = load_vault()
    rows = []
    for obf_key, entry in v.items():
        created = entry.get("created_at", "-")
        updated = entry.get("updated_at", "-")
        rows.append(
            f"<tr><td><code>{obf_key}</code></td><td>{created}</td><td>{updated}</td></tr>"
        )
    table = (
        "<div class='card'>"
        "<h3>Services (Obfuscated)</h3>"
        + (
            "<table style='width:100%'><thead><tr><th>Service Key</th><th>Created</th><th>Updated</th></tr></thead><tbody>"
            + "".join(rows)
            + "</tbody></table>"
            if rows
            else "<p>No services.</p>"
        )
        + "</div>"
    )
    reveal = """
    <div class="card">
      <h3>Reveal Service Name</h3>
      <form method="post" action="/services/reveal">
        <div class="form-grid">
          <div class="field">
            <label>Master Password</label>
            <div class="input-row">
              <input type="password" name="master" required />
              <button type="button" class="btn eye" onclick="const inp=this.previousElementSibling; const wasPwd=inp.type==='password'; inp.type=wasPwd?'text':'password'; this.textContent=inp.type==='password'?'👁️':'🙈'; if(wasPwd){setTimeout(()=>{inp.type='password'; this.textContent='👁️';},3000);}">👁️</button>
            </div>
          </div>
          <div>
            <label>Service Key</label>
            <input type="text" name="key" required />
          </div>
        </div>
        <div class="actions">
          <button type="submit" class="btn">Reveal</button>
        </div>
      </form>
      <p class="hint">Reveal validates your master by decrypting a field, then shows the plaintext service name derived from its key.</p>
    </div>
    """
    return HTMLResponse(BASE_TEMPLATE.render(content=table + reveal))


@app.post("/services/reveal", response_class=HTMLResponse)
def services_reveal(master: str = Form(...), key: str = Form(...)) -> HTMLResponse:
    from .vault import derive_key
    from .vault import _engine as _eng  # reuse engine helpers
    from .vault import deobfuscate

    v = _eng.load_vault()
    entry = v.get(key)
    if not entry:
        content = "<div class='card'><p>Service key not found.</p></div>"
        return HTMLResponse(BASE_TEMPLATE.render(content=content))
    try:
        import base64 as _b64

        salt = _b64.urlsafe_b64decode(entry.get("salt", "").encode("ascii"))
        # Validate master by decrypting username field
        k = derive_key(master, salt)
        cipher = _eng._fernet_from_key(k)
        _ = cipher.decrypt(entry["username"].encode("ascii")).decode("utf-8")
        name = deobfuscate(key, salt)
        content = (
            f"<div class='card'><p>Service name: <strong>{name}</strong></p></div>"
        )
    except Exception:
        content = "<div class='card'><p>Reveal failed: invalid master or key.</p></div>"
    return HTMLResponse(BASE_TEMPLATE.render(content=content))


@app.get("/add", response_class=HTMLResponse)
def add_get() -> HTMLResponse:
    content = """
    <div class="card">
      <h3>Create Password</h3>
      <form method="post">
        <div class="form-grid">
          <div class="field">
            <label>Master Password</label>
            <div class="input-row">
              <input type="password" name="master" required />
              <button type="button" class="btn eye" onclick="const inp=this.previousElementSibling; const wasPwd=inp.type==='password'; inp.type=wasPwd?'text':'password'; this.textContent=inp.type==='password'?'👁️':'🙈'; if(wasPwd){setTimeout(()=>{inp.type='password'; this.textContent='👁️';},3000);}">👁️</button>
            </div>
          </div>
          <div>
            <label>Service Name</label>
            <input type="text" name="service" required />
          </div>
          <div>
            <label>Username</label>
            <input type="text" name="username" required />
          </div>
          <div class="field">
            <label>Password</label>
            <div class="input-row">
              <input type="password" name="password" required />
              <button type="button" class="btn eye" onclick="const inp=this.previousElementSibling; const wasPwd=inp.type==='password'; inp.type=wasPwd?'text':'password'; this.textContent=inp.type==='password'?'👁️':'🙈'; if(wasPwd){setTimeout(()=>{inp.type='password'; this.textContent='👁️';},3000);}">👁️</button>
            </div>
          </div>
          <div style="grid-column: 1 / -1;">
            <label>Source Info</label>
            <textarea name="source" rows="3"></textarea>
          </div>
        </div>
        <div class="actions">
          <button type="submit" class="btn primary">Create</button>
        </div>
      </form>
    </div>
    """
    return HTMLResponse(BASE_TEMPLATE.render(content=content))


@app.post("/add")
def add_post(
    master: str = Form(...),
    service: str = Form(...),
    username: str = Form(...),
    password: str = Form(...),
    source: str = Form(""),
):
    ok = add_entry(master, service, username, password, source)
    if ok:
        content = "<div class='card'><p>Password created successfully.</p></div>"
    else:
        content = "<div class='card'><p>Create failed: invalid input or master password.</p></div>"
    return HTMLResponse(BASE_TEMPLATE.render(content=content))


@app.get("/get", response_class=HTMLResponse)
def get_get() -> HTMLResponse:
    content = """
    <div class="card">
      <h3>Get Entry</h3>
      <form method="post">
        <div class="form-grid">
          <div class="field">
            <label>Master Password</label>
            <div class="input-row">
              <input type="password" name="master" required />
              <button type="button" class="btn eye" onclick="const inp=this.previousElementSibling; const wasPwd=inp.type==='password'; inp.type=wasPwd?'text':'password'; this.textContent=inp.type==='password'?'👁️':'🙈'; if(wasPwd){setTimeout(()=>{inp.type='password'; this.textContent='👁️';},3000);}">👁️</button>
            </div>
          </div>
          <div>
            <label>Service Name</label>
            <input type="text" name="service" required />
          </div>
        </div>
        <div class="actions">
          <button type="submit" class="btn primary">Get</button>
        </div>
      </form>
    </div>
    """
    return HTMLResponse(BASE_TEMPLATE.render(content=content))


@app.post("/get", response_class=HTMLResponse)
def get_post(master: str = Form(...), service: str = Form(...)) -> HTMLResponse:
    entry = get_entry(master, service)
    if entry:
        card = (
            f"<div class='card entry'>"
            f"<strong>{entry['service_name']}</strong>"
            f"<div>Username: {entry['username']}</div>"
            f"<div>Password: <span data-value='{entry['password']}'>••••••••</span> "
            f"<button type='button' class='btn eye' onclick=\"const s=this.previousElementSibling; const h=s.textContent.startsWith('•'); s.textContent=h?s.getAttribute('data-value'):'••••••••'; this.textContent=h?'🙈':'👁️'; if(h){{ setTimeout(()=>{{ s.textContent='••••••••'; this.textContent='👁️'; }},3000); }}\">👁️</button></div>"
            f"<div class='hint'>Source: {entry['source_info']}</div>"
            f"</div>"
        )
    else:
        card = "<div class='card'><p>Not found or wrong master password.</p></div>"
    return HTMLResponse(BASE_TEMPLATE.render(content=card))


@app.get("/search", response_class=HTMLResponse)
def search_get() -> HTMLResponse:
    content = """
    <div class="card">
      <h3>Search</h3>
      <form method="post">
        <div class="form-grid">
          <div class="field">
            <label>Master Password</label>
            <div class="input-row">
              <input type="password" name="master" required />
              <button type="button" class="btn eye" onclick="const inp=this.previousElementSibling; const wasPwd=inp.type==='password'; inp.type=wasPwd?'text':'password'; this.textContent=inp.type==='password'?'👁️':'🙈'; if(wasPwd){setTimeout(()=>{inp.type='password'; this.textContent='👁️';},3000);}">👁️</button>
            </div>
          </div>
          <div>
            <label>Keyword</label>
            <input type="text" name="keyword" required />
          </div>
        </div>
        <div class="actions">
          <button type="submit" class="btn primary">Search</button>
        </div>
      </form>
    </div>
    """
    return HTMLResponse(BASE_TEMPLATE.render(content=content))


@app.post("/search", response_class=HTMLResponse)
def search_post(master: str = Form(...), keyword: str = Form(...)) -> HTMLResponse:
    results = search_entries(master, keyword)
    if not results:
        content = "<div class='card'><p>No matches.</p></div>"
    else:
        cards = [
            f"<div class='card entry'><strong>{r['service_name']}</strong><div>Username: {r['username']}</div><div>Password: {r['password']}</div><div class='hint'>Source: {r['source_info']}</div></div>"
            for r in results
        ]
        content = "".join(cards)
    return HTMLResponse(BASE_TEMPLATE.render(content=content))


@app.get("/export", response_class=HTMLResponse)
def export_get() -> HTMLResponse:
    content = (
        "<div class='card'>"
        "<h3>Export (Encrypted)</h3>"
        "<p>Downloads the encrypted vault file. Plaintext export is disabled.</p>"
        "<div class='actions'>"
        "<a class='btn primary' href='/export/download'>Download Encrypted Vault</a>"
        "</div>"
        "</div>"
    )
    return HTMLResponse(BASE_TEMPLATE.render(content=content))


@app.get("/export/download")
def export_download():
    from .config import DEFAULT_VAULT_PATH
    from fastapi.responses import FileResponse

    try:
        return FileResponse(
            DEFAULT_VAULT_PATH,
            media_type="application/octet-stream",
            filename="vault.enc.json",
        )
    except Exception:
        return HTMLResponse(
            BASE_TEMPLATE.render(
                content="<div class='card'><p>Export failed.</p></div>"
            )
        )


@app.get("/encrypt", response_class=HTMLResponse)
def encrypt_get() -> HTMLResponse:
    content = (
        "<div class='card'>"
        "<h3>Encrypt</h3>"
        "<form method='post'>"
        "<div class='form-grid'>"
        "<div><label>Service Name</label><input type='text' name='service_name' required /></div>"
        "<div><label>Username</label><input type='text' name='username' required /></div>"
        "<div class='field'><label>Password</label><div class='input-row'>"
        "<input type='password' name='password' required />"
        "<button type='button' class='btn eye' onclick=\"const i=this.previousElementSibling; const w=i.type==='password'; i.type=w?'text':'password'; this.textContent=i.type==='password'?'👁️':'🙈'; if(w){setTimeout(()=>{i.type='password'; this.textContent='👁️';},3000)}\">👁️</button>"
        "</div></div>"
        "</div>"
        "<div class='actions'><button type='submit' class='btn primary'>Encrypt</button></div>"
        "</form>"
        "</div>"
    )
    return HTMLResponse(BASE_TEMPLATE.render(content=content))


@app.post("/encrypt", response_class=HTMLResponse)
def encrypt_post(
    service_name: str = Form(...), username: str = Form(...), password: str = Form(...)
) -> HTMLResponse:
    ensure_instance_materials()
    instance_secret = get_instance_secret()
    app_salt = get_app_salt()
    cfg = load_config()
    aad = cfg.get("app_instance_id", "").encode("utf-8")
    key = derive_aes_key(instance_secret, app_salt)
    import json as _json

    payload = _json.dumps(
        {
            "service_name": service_name.strip(),
            "username": username.strip(),
            "password": password,
        },
        separators=(",", ":"),
    ).encode("utf-8")
    nonce_b64, encrypted_b64 = aes_gcm_encrypt(key, payload, aad=aad)
    content = (
        "<div class='card'>"
        "<h3>Encrypted Payload</h3>"
        f"<p><strong>Nonce</strong>: <code>{nonce_b64}</code></p>"
        f"<p><strong>Ciphertext</strong>: <code>{encrypted_b64}</code></p>"
        "<p class='hint'>Store these values securely. They are bound to this app instance.</p>"
        "</div>"
    )
    return HTMLResponse(BASE_TEMPLATE.render(content=content))


@app.get("/decrypt", response_class=HTMLResponse)
def decrypt_get() -> HTMLResponse:
    content = (
        "<div class='card'>"
        "<h3>Decrypt</h3>"
        "<form method='post'>"
        "<div class='form-grid'>"
        "<div class='field'><label>Master Password</label><div class='input-row'>"
        "<input type='password' name='master' required />"
        "<button type='button' class='btn eye' onclick=\"const i=this.previousElementSibling; const w=i.type==='password'; i.type=w?'text':'password'; this.textContent=i.type==='password'?'👁️':'🙈'; if(w){setTimeout(()=>{i.type='password'; this.textContent='👁️';},3000)}\">👁️</button>"
        "</div></div>"
        "<div><label>Nonce (base64)</label><input type='text' name='nonce_b64' required /></div>"
        "<div><label>Ciphertext (base64)</label><input type='text' name='encrypted_b64' required /></div>"
        "</div>"
        "<div class='actions'><button type='submit' class='btn primary'>Decrypt</button></div>"
        "</form>"
        "</div>"
    )
    return HTMLResponse(BASE_TEMPLATE.render(content=content))


@app.post("/decrypt", response_class=HTMLResponse)
def decrypt_post(
    master: str = Form(...), nonce_b64: str = Form(...), encrypted_b64: str = Form(...)
) -> HTMLResponse:
    stored = get_master_password_hash()
    if not stored:
        return HTMLResponse(
            BASE_TEMPLATE.render(
                content="<div class='card'><p>Master password not configured.</p></div>"
            )
        )
    try:
        ok = bcrypt.checkpw(master.encode("utf-8"), stored.encode("utf-8"))
    except Exception:
        ok = False
    if not ok:
        return HTMLResponse(
            BASE_TEMPLATE.render(
                content="<div class='card'><p>Master password invalid.</p></div>"
            )
        )
    ensure_instance_materials()
    instance_secret = get_instance_secret()
    app_salt = get_app_salt()
    cfg = load_config()
    aad = cfg.get("app_instance_id", "").encode("utf-8")
    key = derive_aes_key(instance_secret, app_salt)
    try:
        pt = aes_gcm_decrypt(key, nonce_b64.strip(), encrypted_b64.strip(), aad=aad)
        import json as _json

        data = _json.loads(pt.decode("utf-8"))
        content = (
            "<div class='card'>"
            "<h3>Decrypted Entry</h3>"
            f"<p><strong>Service</strong>: {data.get('service_name', '')}</p>"
            f"<p><strong>Username</strong>: {data.get('username', '')}</p>"
            f"<p><strong>Password</strong>: {data.get('password', '')}</p>"
            "</div>"
        )
    except Exception:
        content = "<div class='card'><p>Failed to decrypt payload.</p></div>"
    return HTMLResponse(BASE_TEMPLATE.render(content=content))


@app.get("/import", response_class=HTMLResponse)
def import_get() -> HTMLResponse:
    content = (
        "<div class='card'>"
        "<h3>Import Encrypted Vault</h3>"
        "<form method='post' enctype='multipart/form-data'>"
        "<div class='form-grid'>"
        "<div class='field'><label>Master Password</label><div class='input-row'>"
        "<input type='password' name='master' required />"
        "<button type='button' class='btn eye' onclick=\"const i=this.previousElementSibling; const w=i.type==='password'; i.type=w?'text':'password'; this.textContent=i.type==='password'?'👁️':'🙈'; if(w){setTimeout(()=>{i.type='password'; this.textContent='👁️';},3000)}\">👁️</button>"
        "</div></div>"
        "<div><label>Encrypted Vault File (.json)</label><input type='file' name='file' accept='application/json,.json' required /></div>"
        "<div style='grid-column: 1 / -1; display: flex; align-items: center; gap: 8px;'>"
        "<input type='checkbox' name='merge' id='merge' />"
        "<label for='merge'>Merge with existing?</label>"
        "</div>"
        "</div>"
        "<div class='actions'><button type='submit' class='btn primary'>Import</button></div>"
        "</form>"
        "</div>"
    )
    return HTMLResponse(BASE_TEMPLATE.render(content=content))


@app.post("/import", response_class=HTMLResponse)
async def import_post(
    master: str = Form(...), merge: bool = Form(False), file: UploadFile = File(...)
) -> HTMLResponse:
    stored = get_master_password_hash()
    try:
        stored_str = stored or ""
        valid = bool(stored_str) and bcrypt.checkpw(
            master.encode("utf-8"), stored_str.encode("utf-8")
        )
    except Exception:
        valid = False
    if not valid:
        return HTMLResponse(
            BASE_TEMPLATE.render(
                content="<div class='card'><p>Master password invalid.</p></div>"
            )
        )
    try:
        ct = (file.content_type or "").lower()
        if not (ct.endswith("json") or ct == "application/json"):
            return HTMLResponse(
                BASE_TEMPLATE.render(
                    content="<div class='card'><p>Invalid file type. Upload a JSON file.</p></div>"
                )
            )
        data = await file.read()
        if len(data) > 5 * 1024 * 1024:
            return HTMLResponse(
                BASE_TEMPLATE.render(
                    content="<div class='card'><p>File too large.</p></div>"
                )
            )
        import json as _json

        new_vault = _json.loads(data.decode("utf-8"))
        if not isinstance(new_vault, dict):
            return HTMLResponse(
                BASE_TEMPLATE.render(
                    content="<div class='card'><p>Invalid vault format.</p></div>"
                )
            )
        sample = next(iter(new_vault.values()), None)
        if not (
            isinstance(sample, dict)
            and all(k in sample for k in ["username", "password", "source", "salt"])
        ):
            return HTMLResponse(
                BASE_TEMPLATE.render(
                    content="<div class='card'><p>Encrypted vault structure not recognized.</p></div>"
                )
            )
        from .vault import load_vault, save_vault

        if merge:
            existing = load_vault()
            existing.update(new_vault)
            ok = save_vault(existing)
        else:
            ok = save_vault(new_vault)
        if not ok:
            return HTMLResponse(
                BASE_TEMPLATE.render(
                    content="<div class='card'><p>Import failed while saving.</p></div>"
                )
            )
        return HTMLResponse(
            BASE_TEMPLATE.render(
                content="<div class='card'><p>Encrypted vault imported successfully.</p></div>"
            )
        )
    except Exception:
        return HTMLResponse(
            BASE_TEMPLATE.render(
                content="<div class='card'><p>Import failed.</p></div>"
            )
        )


@app.get("/delete", response_class=HTMLResponse)
def delete_get() -> HTMLResponse:
    content = """
    <div class="card">
      <h3>Delete Entry</h3>
      <form method="post">
        <div class="form-grid">
          <div class="field">
            <label>Master Password</label>
            <div class="input-row">
              <input type="password" name="master" required />
              <button type="button" class="btn eye" onclick="const inp=this.previousElementSibling; const wasPwd=inp.type==='password'; inp.type=wasPwd?'text':'password'; this.textContent=inp.type==='password'?'👁️':'🙈'; if(wasPwd){setTimeout(()=>{inp.type='password'; this.textContent='👁️';},3000);}">👁️</button>
            </div>
          </div>
          <div>
            <label>Service Name</label>
            <input type="text" name="service" required />
          </div>
        </div>
        <div class="actions">
          <button type="submit" class="btn">Delete</button>
        </div>
      </form>
    </div>
    """
    return HTMLResponse(BASE_TEMPLATE.render(content=content))


@app.post("/delete", response_class=HTMLResponse)
def delete_post(master: str = Form(...), service: str = Form(...)) -> HTMLResponse:
    from .vault import delete_entry as _delete_entry

    ok = _delete_entry(master, service)
    if ok:
        content = "<div class='card'><p>Password deleted successfully.</p></div>"
    else:
        content = "<div class='card'><p>Delete failed: not found or invalid master password.</p></div>"
    return HTMLResponse(BASE_TEMPLATE.render(content=content))


# ----------------------------- Update (HTML) -----------------------------


@app.get("/update", response_class=HTMLResponse)
def update_get() -> HTMLResponse:
    content = """
    <div class="card">
      <h3>Update Entry</h3>
      <form method="post">
        <div class="form-grid">
          <div>
            <label>Master Password</label>
            <input type="password" name="master" required />
          </div>
          <div>
            <label>Service Name</label>
            <input type="text" name="service" required />
          </div>
          <div style="grid-column: 1 / -1;">
            <label>New Password</label>
            <div class="input-row">
              <input type="password" name="new_password" required />
              <button type="button" class="btn eye" onclick="const inp=this.previousElementSibling; const wasPwd=inp.type==='password'; inp.type=wasPwd?'text':'password'; this.textContent=inp.type==='password'?'👁️':'🙈'; if(wasPwd){setTimeout(()=>{inp.type='password'; this.textContent='👁️';},3000);}">👁️</button>
            </div>
            <p class="hint">Min 12 chars, upper, lower, digit, symbol</p>
          </div>
        </div>
        <div class="actions">
          <button type="submit" class="btn primary">Update</button>
        </div>
      </form>
    </div>
    """
    return HTMLResponse(BASE_TEMPLATE.render(content=content))


@app.post("/update")
def update_post(
    master: str = Form(...), service: str = Form(...), new_password: str = Form(...)
):
    # Reuse engine-level update; UI does not enforce strength client-side
    # Import locally to avoid top-level attribute resolution issues in some analyzers
    from .vault import update_entry as _update_entry  # type: ignore[attr-defined]

    ok = _update_entry(master, service, password=new_password)
    if ok:
        content = "<div class='card'><p>Password updated successfully.</p></div>"
    else:
        content = "<div class='card'><p>Update failed: not found or invalid master password.</p></div>"
    return HTMLResponse(BASE_TEMPLATE.render(content=content))


# -------------------------- Master Management ---------------------------


@app.get("/master", response_class=HTMLResponse)
def master_home() -> HTMLResponse:
    content = """
    <div class="grid grid-2">
      <div class="card">
        <h3>Setup Master</h3>
        <p class="hint">Create a new master password to unlock the vault.</p>
        <div class="actions"><a class="btn primary" href="/master/setup">Setup</a></div>
      </div>
      <div class="card">
        <h3>Update Master</h3>
        <p class="hint">Change master password and re-encrypt all existing entries.</p>
        <div class="actions"><a class="btn" href="/master/update">Update</a></div>
      </div>
      <div class="card">
        <h3>Delete Master</h3>
        <p class="hint">Wipes the vault and clears the master password. Irreversible.</p>
        <div class="actions"><a class="btn" href="/master/delete">Delete</a></div>
      </div>
    </div>
    """
    return HTMLResponse(BASE_TEMPLATE.render(content=content))


@app.get("/master/setup", response_class=HTMLResponse)
def master_setup_get() -> HTMLResponse:
    content = """
    <div class="card">
      <h3>Setup Master Password</h3>
      <form method="post">
        <div class="form-grid">
          <div class="field">
            <label>New Master Password</label>
            <div class="input-row">
              <input type="password" name="password" required />
              <button type="button" class="btn eye" onclick="const inp=this.previousElementSibling; const wasPwd=inp.type==='password'; inp.type=wasPwd?'text':'password'; this.textContent=inp.type==='password'?'👁️':'🙈'; if(wasPwd){setTimeout(()=>{inp.type='password'; this.textContent='👁️';},3000);}">👁️</button>
            </div>
          </div>
          <div class="field">
            <label>Confirm Password</label>
            <div class="input-row">
              <input type="password" name="confirm" required />
              <button type="button" class="btn eye" onclick="this.previousElementSibling.type=this.previousElementSibling.type==='password'?'text':'password'; this.textContent=this.previousElementSibling.type==='password'?'👁️':'🙈';">👁️</button>
            </div>
          </div>
        </div>
        <p class="hint">Min 12 chars, upper, lower, digit, symbol</p>
        <div class="actions">
          <button type="submit" class="btn primary">Setup</button>
        </div>
      </form>
    </div>
    """
    return HTMLResponse(BASE_TEMPLATE.render(content=content))


@app.post("/master/setup", response_class=HTMLResponse)
def master_setup_post(
    password: str = Form(...), confirm: str = Form(...)
) -> HTMLResponse:
    if password != confirm:
        content = "<div class='card'><p>Passwords do not match.</p></div>"
        return HTMLResponse(BASE_TEMPLATE.render(content=content))
    if not is_strong_password(password):
        content = "<div class='card'><p>Weak password. Min 12 chars with upper/lower/digit/special.</p></div>"
        return HTMLResponse(BASE_TEMPLATE.render(content=content))
    if get_master_password_hash():
        content = "<div class='card'><p>Master password already set.</p></div>"
        return HTMLResponse(BASE_TEMPLATE.render(content=content))
    cfg = load_config()
    rounds = int(cfg.get("bcrypt_rounds", 14))
    salt = bcrypt.gensalt(rounds)
    hash_str = bcrypt.hashpw(password.encode("utf-8"), salt).decode("utf-8")
    set_master_password_hash(hash_str)
    try:
        cfg["master_set_count"] = int(cfg.get("master_set_count", 0)) + 1
        cfg["last_master_set_at"] = (
            __import__("datetime").datetime.utcnow().isoformat() + "Z"
        )
        from .config import save_config

        save_config(cfg)
    except Exception:
        pass
    content = "<div class='card'><p>Master password configured.</p></div>"
    return HTMLResponse(BASE_TEMPLATE.render(content=content))


@app.get("/master/update", response_class=HTMLResponse)
def master_update_get() -> HTMLResponse:
    content = """
    <div class="card">
      <h3>Update Master Password</h3>
      <form method="post">
        <div class="form-grid">
          <div class="field">
            <label>Current Master Password</label>
            <div class="input-row">
              <input type="password" name="old" required />
              <button type="button" class="btn eye" onclick="this.previousElementSibling.type=this.previousElementSibling.type==='password'?'text':'password'; this.textContent=this.previousElementSibling.type==='password'?'👁️':'🙈';">👁️</button>
            </div>
          </div>
          <div class="field">
            <label>New Master Password</label>
            <div class="input-row">
              <input type="password" name="new" required />
              <button type="button" class="btn eye" onclick="this.previousElementSibling.type=this.previousElementSibling.type==='password'?'text':'password'; this.textContent=this.previousElementSibling.type==='password'?'👁️':'🙈';">👁️</button>
            </div>
          </div>
          <div class="field">
            <label>Confirm New Password</label>
            <div class="input-row">
              <input type="password" name="confirm" required />
              <button type="button" class="btn eye" onclick="this.previousElementSibling.type=this.previousElementSibling.type==='password'?'text':'password'; this.textContent=this.previousElementSibling.type==='password'?'👁️':'🙈';">👁️</button>
            </div>
          </div>
        </div>
        <p class="hint">Re-encrypts all entries with the new master.</p>
        <div class="actions">
          <button type="submit" class="btn primary">Update</button>
        </div>
      </form>
    </div>
    """
    return HTMLResponse(BASE_TEMPLATE.render(content=content))


@app.post("/master/update", response_class=HTMLResponse)
def master_update_post(
    old: str = Form(...), new: str = Form(...), confirm: str = Form(...)
) -> HTMLResponse:
    if new != confirm:
        content = "<div class='card'><p>New passwords do not match.</p></div>"
        return HTMLResponse(BASE_TEMPLATE.render(content=content))
    if not is_strong_password(new):
        content = "<div class='card'><p>Weak new password.</p></div>"
        return HTMLResponse(BASE_TEMPLATE.render(content=content))
    stored = get_master_password_hash()
    try:
        stored_str = stored or ""
        valid = bool(stored_str) and bcrypt.checkpw(
            old.encode("utf-8"), stored_str.encode("utf-8")
        )
    except Exception:
        valid = False
    if not valid:
        content = "<div class='card'><p>Current master password invalid.</p></div>"
        return HTMLResponse(BASE_TEMPLATE.render(content=content))
    from .vault import rotate_master_password

    count = rotate_master_password(old, new)
    if count <= 0:
        content = "<div class='card'><p>No entries updated. Verify current master password.</p></div>"
        return HTMLResponse(BASE_TEMPLATE.render(content=content))
    cfg = load_config()
    rounds = int(cfg.get("bcrypt_rounds", 14))
    salt = bcrypt.gensalt(rounds)
    hash_str = bcrypt.hashpw(new.encode("utf-8"), salt).decode("utf-8")
    set_master_password_hash(hash_str)
    try:
        cfg["rotations_count"] = int(cfg.get("rotations_count", 0)) + 1
        cfg["last_rotation_at"] = (
            __import__("datetime").datetime.utcnow().isoformat() + "Z"
        )
        from .config import save_config

        save_config(cfg)
    except Exception:
        pass
    content = f"<div class='card'><p>Master password updated. Re-encrypted {count} entries.</p></div>"
    return HTMLResponse(BASE_TEMPLATE.render(content=content))


@app.get("/master/delete", response_class=HTMLResponse)
def master_delete_get() -> HTMLResponse:
    content = """
    <div class="card">
      <h3>Delete Master Password</h3>
      <p class="hint">This will wipe all entries and clear the master password. This cannot be undone.</p>
      <form method="post">
        <div class="form-grid">
          <div class="field">
            <label>Current Master Password</label>
            <div class="input-row">
              <input type="password" name="old" required />
              <button type="button" class="btn eye" onclick="this.previousElementSibling.type=this.previousElementSibling.type==='password'?'text':'password'; this.textContent=this.previousElementSibling.type==='password'?'👁️':'🙈';">👁️</button>
            </div>
          </div>
          <div style="grid-column: 1 / -1; display: flex; align-items: center; gap: 8px;">
            <input type="checkbox" id="confirmwipe" name="confirmwipe" required />
            <label for="confirmwipe">I understand this wipes all data</label>
          </div>
        </div>
        <div class="actions">
          <button type="submit" class="btn">Delete</button>
        </div>
      </form>
    </div>
    """
    return HTMLResponse(BASE_TEMPLATE.render(content=content))


@app.post("/master/delete", response_class=HTMLResponse)
def master_delete_post(
    old: str = Form(...), confirmwipe: bool = Form(False)
) -> HTMLResponse:
    if not confirmwipe:
        content = "<div class='card'><p>Confirmation required to wipe vault.</p></div>"
        return HTMLResponse(BASE_TEMPLATE.render(content=content))
    stored = get_master_password_hash()
    try:
        stored_str = stored or ""
        valid = bool(stored_str) and bcrypt.checkpw(
            old.encode("utf-8"), stored_str.encode("utf-8")
        )
    except Exception:
        valid = False
    if not valid:
        content = "<div class='card'><p>Current master password invalid.</p></div>"
        return HTMLResponse(BASE_TEMPLATE.render(content=content))
    from .vault import wipe_vault

    ok = wipe_vault()
    if ok:
        clear_master_password_hash()
        content = (
            "<div class='card'><p>Vault wiped and master password cleared.</p></div>"
        )
    else:
        content = "<div class='card'><p>Wipe failed.</p></div>"
    return HTMLResponse(BASE_TEMPLATE.render(content=content))


@app.get("/reset", response_class=HTMLResponse)
def reset_get() -> HTMLResponse:
    content = """
    <div class="card">
      <h3>Reset Vault</h3>
      <p class="hint">Clears all entries and the master password. This cannot be undone.</p>
      <form method="post">
        <div class="form-grid">
          <div class="field">
            <label>Master Password</label>
            <div class="input-row">
              <input type="password" name="old" required />
              <button type="button" class="btn eye" onclick="const inp=this.previousElementSibling; const wasPwd=inp.type==='password'; inp.type=wasPwd?'text':'password'; this.textContent=inp.type==='password'?'👁️':'🙈'; if(wasPwd){setTimeout(()=>{inp.type='password'; this.textContent='👁️';},3000);}">👁️</button>
            </div>
          </div>
          <div style="grid-column: 1 / -1; display: flex; align-items: center; gap: 8px;">
            <input type="checkbox" id="confirmreset" name="confirmreset" required />
            <label for="confirmreset">I understand this action resets all data</label>
          </div>
        </div>
        <div class="actions">
          <button type="submit" class="btn">Reset</button>
        </div>
      </form>
    </div>
    """
    return HTMLResponse(BASE_TEMPLATE.render(content=content))


@app.post("/reset", response_class=HTMLResponse)
def reset_post(old: str = Form(...), confirmreset: bool = Form(False)) -> HTMLResponse:
    if not confirmreset:
        content = "<div class='card'><p>Confirmation required to reset vault.</p></div>"
        return HTMLResponse(BASE_TEMPLATE.render(content=content))
    stored = get_master_password_hash()
    try:
        stored_str = stored or ""
        valid = bool(stored_str) and bcrypt.checkpw(
            old.encode("utf-8"), stored_str.encode("utf-8")
        )
    except Exception:
        valid = False
    if not valid:
        content = "<div class='card'><p>Current master password invalid.</p></div>"
        return HTMLResponse(BASE_TEMPLATE.render(content=content))
    from .vault import wipe_vault

    ok = wipe_vault()
    if ok:
        clear_master_password_hash()
        content = "<div class='card'><p>Vault reset successfully.</p></div>"
    else:
        content = "<div class='card'><p>Reset failed.</p></div>"
    return HTMLResponse(BASE_TEMPLATE.render(content=content))
