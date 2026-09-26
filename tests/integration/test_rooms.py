import asyncio
import uuid
from typing import Any

import pytest
from httpx import ASGITransport, AsyncClient

from app.db.mongo import ensure_indexes
from app.db.redis_client import redis_client
from app.main import app
from app.services.realtime import room_channel

# Les clients Mongo/Redis sont des singletons liés à la boucle asyncio de session.
pytestmark = pytest.mark.asyncio(loop_scope="session")

STRONG_PASSWORD = "Sup3r$ecretPass!"


@pytest.fixture(autouse=True)
async def _prepare_indexes() -> None:
    await ensure_indexes()


def _unique_email() -> str:
    return f"user-{uuid.uuid4().hex}@example.com"


async def _register(client: AsyncClient, username: str, public_key: str) -> dict[str, Any]:
    """Inscrit un utilisateur et pousse une clé publique factice (opaque pour le serveur)."""
    response = await client.post(
        "/auth/register",
        json={"username": username, "email": _unique_email(), "password": STRONG_PASSWORD},
    )
    assert response.status_code == 201

    csrf_token = client.cookies.get("csrf_token")
    key_response = await client.put(
        "/users/me/public-key",
        json={"public_key": public_key},
        headers={"X-CSRF-Token": csrf_token},
    )
    assert key_response.status_code == 200
    return key_response.json()


async def _wait_for_published_message(pubsub: Any, timeout: float = 2.0) -> dict[str, Any] | None:
    deadline = asyncio.get_event_loop().time() + timeout
    while True:
        remaining = deadline - asyncio.get_event_loop().time()
        if remaining <= 0:
            return None
        message = await pubsub.get_message(timeout=remaining)
        if message and message["type"] == "message":
            return message


async def test_dm_flow_creates_room_stores_and_lists_messages() -> None:
    async with (
        AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as alice_client,
        AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as bob_client,
    ):
        alice = await _register(alice_client, "alice", "alice-pubkey")
        bob = await _register(bob_client, "bob", "bob-pubkey")

        create_response = await alice_client.post(
            "/rooms/dm", json={"username": "bob", "discriminator": bob["discriminator"]}
        )
        assert create_response.status_code == 200
        room = create_response.json()
        assert room["peer"]["username"] == "bob"
        assert room["peer"]["public_key"] == "bob-pubkey"
        room_id = room["id"]

        # Idempotent : Bob qui recrée le DM retombe sur le même salon.
        bob_room_response = await bob_client.post(
            "/rooms/dm", json={"username": "alice", "discriminator": alice["discriminator"]}
        )
        assert bob_room_response.status_code == 200
        assert bob_room_response.json()["id"] == room_id

        csrf_token = alice_client.cookies.get("csrf_token")
        send_response = await alice_client.post(
            f"/rooms/{room_id}/messages",
            json={"ciphertext": "cipher-abc", "iv": "iv-123"},
            headers={"X-CSRF-Token": csrf_token},
        )
        assert send_response.status_code == 201
        message = send_response.json()
        assert message["ciphertext"] == "cipher-abc"
        assert message["sender_id"] == alice["id"]

        history_response = await bob_client.get(f"/rooms/{room_id}/messages")
        assert history_response.status_code == 200
        history = history_response.json()
        assert len(history) == 1
        assert history[0]["ciphertext"] == "cipher-abc"

        rooms_response = await alice_client.get("/rooms")
        assert rooms_response.status_code == 200
        assert rooms_response.json()[0]["peer"]["username"] == "bob"


async def test_non_member_cannot_read_or_post_messages() -> None:
    async with (
        AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as alice_client,
        AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as bob_client,
        AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as intruder_client,
    ):
        await _register(alice_client, "carol", "carol-pubkey")
        bob = await _register(bob_client, "dave", "dave-pubkey")
        await _register(intruder_client, "eve", "eve-pubkey")

        create_response = await alice_client.post(
            "/rooms/dm", json={"username": "dave", "discriminator": bob["discriminator"]}
        )
        room_id = create_response.json()["id"]

        response = await intruder_client.get(f"/rooms/{room_id}/messages")
        assert response.status_code == 404


async def test_cannot_dm_yourself() -> None:
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        user = await _register(client, "frank", "frank-pubkey")

        response = await client.post(
            "/rooms/dm", json={"username": "frank", "discriminator": user["discriminator"]}
        )

        assert response.status_code == 400


async def test_sending_message_publishes_to_redis_channel() -> None:
    async with (
        AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as alice_client,
        AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as bob_client,
    ):
        await _register(alice_client, "gina", "gina-pubkey")
        bob = await _register(bob_client, "harry", "harry-pubkey")

        create_response = await alice_client.post(
            "/rooms/dm", json={"username": "harry", "discriminator": bob["discriminator"]}
        )
        room_id = create_response.json()["id"]

        pubsub = redis_client.pubsub()
        await pubsub.subscribe(room_channel(room_id))
        try:
            csrf_token = alice_client.cookies.get("csrf_token")
            await alice_client.post(
                f"/rooms/{room_id}/messages",
                json={"ciphertext": "cipher-xyz", "iv": "iv-456"},
                headers={"X-CSRF-Token": csrf_token},
            )

            published = await _wait_for_published_message(pubsub)
            assert published is not None
            assert "cipher-xyz" in published["data"]
        finally:
            await pubsub.unsubscribe(room_channel(room_id))
            await pubsub.aclose()
