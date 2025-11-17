from fastapi.testclient import TestClient
from vault.gui_web import app


def test_web_add_and_get():
    client = TestClient(app)
    # Add
    resp = client.post("/add", data={
        "master": "StrongMasterPass123!",
        "service": "testsvc",
        "username": "alice",
        "password": "pw",
        "source": "src",
    })
    assert resp.status_code in (200, 303)
    # Get
    resp = client.post("/get", data={
        "master": "StrongMasterPass123!",
        "service": "testsvc",
    })
    assert resp.status_code == 200
    assert "alice" in resp.text