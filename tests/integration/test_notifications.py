import asyncio
import uuid
from typing import Any

import pytest
from httpx import ASGITransport, AsyncClient

from app.db.mongo import ensure_indexes
from app.db.redis_client import redis_client
from app.main import app
from app.services.realtime import notification_channel

pytestmark = pytest.mark.asyncio(loop_scope="session")

STRONG_PASSWORD = "Sup3r$ecretPass!"


@pytest.fixture(autouse=True)
async def _prepare_indexes() -> None:
    await ensure_indexes()


def _unique_email() -> str:
    return f"user-{uuid.uuid4().hex}@example.com"


async def _register(client: AsyncClient, username: str) -> dict[str, Any]:
    response = await client.post(
        "/auth/register",
        json={"username": username, "email": _unique_email(), "password": STRONG_PASSWORD},
    )
    assert response.status_code == 201
    return response.json()


def _csrf(client: AsyncClient) -> dict[str, str]:
    return {"X-CSRF-Token": client.cookies.get("csrf_token")}


async def _wait_for_published_message(pubsub: Any, timeout: float = 2.0) -> dict[str, Any] | None:
    deadline = asyncio.get_event_loop().time() + timeout
    while True:
        remaining = deadline - asyncio.get_event_loop().time()
        if remaining <= 0:
            return None
        message = await pubsub.get_message(timeout=remaining)
        if message and message["type"] == "message":
            return message


async def test_message_creates_notification_for_recipient() -> None:
    async with (
        AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as alice_client,
        AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as bob_client,
    ):
        alice = await _register(alice_client, "notifalice")
        bob = await _register(bob_client, "notifbob")

        room = (
            await alice_client.post(
                "/rooms/dm",
                json={"username": "notifbob", "discriminator": bob["discriminator"]},
            )
        ).json()

        pubsub = redis_client.pubsub()
        await pubsub.subscribe(notification_channel(bob["id"]))
        try:
            await alice_client.post(
                f"/rooms/{room['id']}/messages",
                json={"ciphertext": "hello-cipher", "iv": "iv"},
                headers=_csrf(alice_client),
            )

            published = await _wait_for_published_message(pubsub)
            assert published is not None
            assert "message" in published["data"]
        finally:
            await pubsub.unsubscribe(notification_channel(bob["id"]))
            await pubsub.aclose()

        notifications = (await bob_client.get("/notifications")).json()
        assert notifications[0]["type"] == "message"
        assert notifications[0]["payload"]["sender_id"] == alice["id"]
        assert notifications[0]["read"] is False

        # Alice n'a pas de notification pour son propre message.
        alice_notifications = (await alice_client.get("/notifications")).json()
        assert alice_notifications == []


async def test_friend_request_and_acceptance_create_notifications() -> None:
    async with (
        AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as alice_client,
        AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as bob_client,
    ):
        alice = await _register(alice_client, "notifcarol")
        bob = await _register(bob_client, "notifdave")

        await alice_client.post(
            "/friends/requests",
            json={"username": "notifdave", "discriminator": bob["discriminator"]},
            headers=_csrf(alice_client),
        )

        bob_notifications = (await bob_client.get("/notifications")).json()
        assert bob_notifications[0]["type"] == "friend_request"
        assert bob_notifications[0]["payload"]["from_user_id"] == alice["id"]

        request_id = bob_notifications[0]["payload"]["request_id"]
        await bob_client.post(
            f"/friends/requests/{request_id}/accept", headers=_csrf(bob_client)
        )

        alice_notifications = (await alice_client.get("/notifications")).json()
        assert alice_notifications[0]["type"] == "friend_accepted"
        assert alice_notifications[0]["payload"]["peer_id"] == bob["id"]


async def test_adding_group_member_creates_room_invite_notification() -> None:
    async with (
        AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as owner_client,
        AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as member_client,
    ):
        await _register(owner_client, "notifowner")
        member = await _register(member_client, "notifmember")

        room = (
            await owner_client.post(
                "/rooms/groups", json={"name": "Groupe notif"}, headers=_csrf(owner_client)
            )
        ).json()
        await owner_client.post(
            f"/rooms/{room['id']}/members",
            json={"username": "notifmember", "discriminator": member["discriminator"]},
            headers=_csrf(owner_client),
        )

        notifications = (await member_client.get("/notifications")).json()
        assert notifications[0]["type"] == "room_invite"
        assert notifications[0]["payload"]["room_id"] == room["id"]


async def test_mark_notification_as_read_and_read_all() -> None:
    async with (
        AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as alice_client,
        AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as bob_client,
    ):
        bob = await _register(bob_client, "notifbob2")
        await _register(alice_client, "notifalice2")

        await alice_client.post(
            "/friends/requests",
            json={"username": "notifbob2", "discriminator": bob["discriminator"]},
            headers=_csrf(alice_client),
        )
        await alice_client.post(
            "/friends/requests",
            json={"username": "notifbob2", "discriminator": bob["discriminator"]},
            headers=_csrf(alice_client),
        )  # doublon rejeté, mais laisse au moins une notif à lire

        notifications = (await bob_client.get("/notifications")).json()
        notification_id = notifications[0]["id"]

        read_response = await bob_client.post(
            f"/notifications/{notification_id}/read", headers=_csrf(bob_client)
        )
        assert read_response.status_code == 200
        assert read_response.json()["read"] is True

        read_all_response = await bob_client.post(
            "/notifications/read-all", headers=_csrf(bob_client)
        )
        assert read_all_response.status_code == 204

        notifications_after = (await bob_client.get("/notifications")).json()
        assert all(notification["read"] for notification in notifications_after)
