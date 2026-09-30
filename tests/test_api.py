import uuid

import pytest
from httpx import ASGITransport, AsyncClient

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


@pytest.mark.asyncio
async def test_authenticated_channel_message_flow_rejects_missing_csrf() -> None:
    username = f"user_{uuid.uuid4().hex[:8]}"
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        registered = await client.post(
            "/api/auth/register",
            json={"username": username, "password": "correct horse battery staple"},
        )
        assert registered.status_code == 201
        csrf = client.cookies.get("talk_csrf")
        assert csrf

        rejected = await client.post("/api/servers", json={"name": "General"})
        assert rejected.status_code == 403

        created_server = await client.post(
            "/api/servers",
            json={"name": "General"},
            headers={"X-CSRF-Token": csrf},
        )
        assert created_server.status_code == 201
        server_id = created_server.json()["id"]

        created_channel = await client.post(
            f"/api/servers/{server_id}/channels",
            json={"name": "discussion"},
            headers={"X-CSRF-Token": csrf},
        )
        assert created_channel.status_code == 201
        channel_id = created_channel.json()["id"]

        created_message = await client.post(
            f"/api/channels/{channel_id}/messages",
            json={"ciphertext": "ciphertext-only", "nonce": "random-nonce", "key_version": "1"},
            headers={"X-CSRF-Token": csrf},
        )
        assert created_message.status_code == 201
        assert created_message.json()["ciphertext"] == "ciphertext-only"
        assert "plaintext" not in created_message.json()

        messages = await client.get(f"/api/channels/{channel_id}/messages")
        assert messages.status_code == 200
        assert messages.json()[0]["ciphertext"] == "ciphertext-only"
