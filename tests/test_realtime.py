import uuid

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.security import sessions
from app.store import store


@pytest.fixture(autouse=True)
def reset_state() -> None:
    store.users.clear()
    store.servers.clear()
    store.channels.clear()
    store.messages.clear()
    sessions.clear()


def test_authenticated_websocket_receives_encrypted_message() -> None:
    username = f"ws_{uuid.uuid4().hex[:8]}"
    with TestClient(app) as client:
        registered = client.post(
            "/api/auth/register",
            json={"username": username, "password": "correct horse battery staple"},
        )
        assert registered.status_code == 201
        csrf = client.cookies.get("talk_csrf")
        headers = {"X-CSRF-Token": csrf}

        server = client.post("/api/servers", json={"name": "Realtime"}, headers=headers)
        channel = client.post(
            f"/api/servers/{server.json()['id']}/channels",
            json={"name": "live"},
            headers=headers,
        )
        channel_id = channel.json()["id"]

        with client.websocket_connect(f"/ws/channels/{channel_id}") as socket:
            created = client.post(
                f"/api/channels/{channel_id}/messages",
                json={"ciphertext": "opaque-value", "nonce": "nonce-value", "key_version": "1"},
                headers=headers,
            )
            assert created.status_code == 201
            assert socket.receive_json()["ciphertext"] == "opaque-value"


def test_frontend_is_served() -> None:
    with TestClient(app) as client:
        response = client.get("/")

    assert response.status_code == 200
    assert "messagerie privée" in response.text
