import uuid
from typing import Any

import pytest
from httpx import ASGITransport, AsyncClient

from app.db.mongo import ensure_indexes
from app.main import app

# Les clients Mongo/Redis sont des singletons liés à la boucle asyncio de session.
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


async def test_send_accept_list_and_revoke_friendship() -> None:
    async with (
        AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as alice_client,
        AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as bob_client,
    ):
        _alice = await _register(alice_client, "alicef")
        bob = await _register(bob_client, "bobf")

        send_response = await alice_client.post(
            "/friends/requests",
            json={"username": "bobf", "discriminator": bob["discriminator"]},
            headers=_csrf(alice_client),
        )
        assert send_response.status_code == 200
        assert send_response.json()["status"] == "pending"

        incoming_response = await bob_client.get("/friends/requests")
        assert incoming_response.status_code == 200
        incoming = incoming_response.json()
        assert len(incoming) == 1
        assert incoming[0]["direction"] == "incoming"
        assert incoming[0]["peer"]["username"] == "alicef"
        request_id = incoming[0]["id"]

        accept_response = await bob_client.post(
            f"/friends/requests/{request_id}/accept", headers=_csrf(bob_client)
        )
        assert accept_response.status_code == 200
        assert accept_response.json()["peer"]["username"] == "alicef"

        alice_friends = await alice_client.get("/friends")
        assert alice_friends.status_code == 200
        assert alice_friends.json()[0]["peer"]["username"] == "bobf"

        bob_friends = await bob_client.get("/friends")
        assert bob_friends.json()[0]["peer"]["username"] == "alicef"

        revoke_response = await alice_client.delete(
            f"/friends/{bob['id']}", headers=_csrf(alice_client)
        )
        assert revoke_response.status_code == 204

        alice_friends_after = await alice_client.get("/friends")
        assert alice_friends_after.json() == []


async def test_mutual_request_auto_accepts() -> None:
    async with (
        AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as alice_client,
        AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as bob_client,
    ):
        alice = await _register(alice_client, "carolf")
        bob = await _register(bob_client, "davef")

        await alice_client.post(
            "/friends/requests",
            json={"username": "davef", "discriminator": bob["discriminator"]},
            headers=_csrf(alice_client),
        )

        # Bob demande Alice en retour : doit accepter directement, pas de doublon.
        reciprocal_response = await bob_client.post(
            "/friends/requests",
            json={"username": "carolf", "discriminator": alice["discriminator"]},
            headers=_csrf(bob_client),
        )
        assert reciprocal_response.status_code == 200
        assert reciprocal_response.json()["status"] == "accepted"

        assert (await alice_client.get("/friends")).json()[0]["peer"]["username"] == "davef"
        assert (await bob_client.get("/friends/requests")).json() == []


async def test_decline_incoming_request() -> None:
    async with (
        AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as alice_client,
        AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as bob_client,
    ):
        _alice = await _register(alice_client, "erinf")
        bob = await _register(bob_client, "frankf")

        await alice_client.post(
            "/friends/requests",
            json={"username": "frankf", "discriminator": bob["discriminator"]},
            headers=_csrf(alice_client),
        )
        request_id = (await bob_client.get("/friends/requests")).json()[0]["id"]

        decline_response = await bob_client.delete(
            f"/friends/requests/{request_id}", headers=_csrf(bob_client)
        )
        assert decline_response.status_code == 204
        assert (await bob_client.get("/friends/requests")).json() == []
        assert (await alice_client.get("/friends")).json() == []


async def test_cannot_friend_yourself() -> None:
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        user = await _register(client, "gracef")

        response = await client.post(
            "/friends/requests",
            json={"username": "gracef", "discriminator": user["discriminator"]},
            headers=_csrf(client),
        )

        assert response.status_code == 400


async def test_duplicate_pending_request_returns_409() -> None:
    async with (
        AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as alice_client,
        AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as bob_client,
    ):
        await _register(alice_client, "helenf")
        bob = await _register(bob_client, "ianf")

        payload = {"username": "ianf", "discriminator": bob["discriminator"]}
        first = await alice_client.post(
            "/friends/requests", json=payload, headers=_csrf(alice_client)
        )
        assert first.status_code == 200

        second = await alice_client.post(
            "/friends/requests", json=payload, headers=_csrf(alice_client)
        )
        assert second.status_code == 409
