import json
import os

from fastapi.testclient import TestClient

from vault.gui_web import app


def _setup_master(client: TestClient) -> None:
    # Reset master hash for isolation
    cfg_path = os.path.join(os.path.dirname(__file__), "..", "vault", "storage", "config.json")
    try:
        with open(cfg_path, "r+", encoding="utf-8") as f:
            cfg = json.load(f)
            cfg.pop("master_password_hash", None)
            f.seek(0)
            json.dump(cfg, f, indent=2)
            f.truncate()
    except Exception:
        pass
    # Get CSRF token
    resp = client.get("/api/auth/csrf-token")
    assert resp.status_code == 200
    token = resp.json()["data"]["csrf_token"]
    # Setup master (idempotent)
    resp = client.post(
        "/api/auth/setup-master",
        headers={"X-CSRF-Token": token, "Content-Type": "application/json"},
        json={"password": "StrongMasterPass123!", "confirm": "StrongMasterPass123!", "masked": True},
    )
    assert resp.status_code in (201, 409)


def test_api_update_password_json():
    client = TestClient(app)
    _setup_master(client)

    # Add an entry via HTML form for simplicity
    resp = client.post(
        "/add",
        data={
            "master": "StrongMasterPass123!",
            "service": "svc-update-json",
            "username": "alice",
            "password": "initialPw1!",
            "source": "src",
        },
    )
    assert resp.status_code in (200, 303)

    # Get CSRF token
    token = client.get("/api/auth/csrf-token").json()["data"]["csrf_token"]

    # Successful update
    resp = client.post(
        "/api/passwords/update",
        headers={"X-CSRF-Token": token, "Content-Type": "application/json"},
        json={
            "service_name": "svc-update-json",
            "new_password": "NewStr0ng!Passw0rd",
            "master_password": "StrongMasterPass123!",
        },
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["success"] and data["code"] == "updated"

    # Weak password (validation yields 422)
    resp = client.post(
        "/api/passwords/update",
        headers={"X-CSRF-Token": token, "Content-Type": "application/json"},
        json={
            "service_name": "svc-update-json",
            "new_password": "weak",
            "master_password": "StrongMasterPass123!",
        },
    )
    assert resp.status_code == 422

    # Wrong master
    resp = client.post(
        "/api/passwords/update",
        headers={"X-CSRF-Token": token, "Content-Type": "application/json"},
        json={
            "service_name": "svc-update-json",
            "new_password": "AnotherStr0ng!Pw",
            "master_password": "WrongMaster123!",
        },
    )
    assert resp.status_code == 401

    # Not found
    resp = client.post(
        "/api/passwords/update",
        headers={"X-CSRF-Token": token, "Content-Type": "application/json"},
        json={
            "service_name": "unknown-service",
            "new_password": "AnotherStr0ng!Pw",
            "master_password": "StrongMasterPass123!",
        },
    )
    assert resp.status_code == 404


def test_ui_update_form():
    client = TestClient(app)
    # Add entry
    resp = client.post(
        "/add",
        data={
            "master": "StrongMasterPass123!",
            "service": "svc-update-form",
            "username": "bob",
            "password": "pw",
            "source": "src",
        },
    )
    assert resp.status_code in (200, 303)

    # Update via HTML form
    resp = client.post(
        "/update",
        data={
            "master": "StrongMasterPass123!",
            "service": "svc-update-form",
            "new_password": "NewStrongPass123!",
        },
    )
    assert resp.status_code == 200
    assert "Updated password for" in resp.text