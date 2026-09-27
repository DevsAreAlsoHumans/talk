import uuid
from typing import Any

import pytest
from httpx import ASGITransport, AsyncClient

from app.db.mongo import ensure_indexes
from app.main import app

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


# Le salon #général est un singleton partagé entre tous les tests (index unique
# sur is_general) : ces tests ne supposent jamais être les premiers à le
# rejoindre, seulement des propriétés vraies quel que soit l'état accumulé.


async def test_general_room_is_shared_by_all_joiners() -> None:
    async with (
        AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as alice,
        AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as bob,
    ):
        alice_user = await _register(alice, "generalalice")
        bob_user = await _register(bob, "generalbob")

        room_alice = (await alice.post("/rooms/general/join", headers=_csrf(alice))).json()
        room_bob = (await bob.post("/rooms/general/join", headers=_csrf(bob))).json()

        assert room_alice["id"] == room_bob["id"]
        assert room_alice["name"] == "Général"

        member_ids = {m["user"]["id"] for m in room_bob["members"]}
        assert {alice_user["id"], bob_user["id"]} <= member_ids

        bob_role = next(m["role"] for m in room_bob["members"] if m["user"]["id"] == bob_user["id"])
        # Le tout premier arrivant devient owner ; tous les suivants sont de
        # simples membres (la rotation de clé est ouverte à tout membre, pas
        # besoin d'un rôle admin pour ça — voir test_group_keys.py).
        assert bob_role in ("owner", "member")


async def test_joining_twice_does_not_duplicate_membership() -> None:
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        carol = await _register(client, "generalcarol")

        first = await client.post("/rooms/general/join", headers=_csrf(client))
        second = await client.post("/rooms/general/join", headers=_csrf(client))

        assert first.json()["id"] == second.json()["id"]
        carol_occurrences = sum(
            1 for m in second.json()["members"] if m["user"]["id"] == carol["id"]
        )
        assert carol_occurrences == 1


async def test_general_room_appears_in_room_list_for_all_joiners() -> None:
    async with (
        AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as alice,
        AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as bob,
    ):
        await _register(alice, "generaldave")
        await _register(bob, "generaleve")

        room = (await alice.post("/rooms/general/join", headers=_csrf(alice))).json()
        await bob.post("/rooms/general/join", headers=_csrf(bob))

        alice_rooms = (await alice.get("/rooms")).json()
        bob_rooms = (await bob.get("/rooms")).json()

        assert any(r["id"] == room["id"] for r in alice_rooms)
        assert any(r["id"] == room["id"] for r in bob_rooms)


async def test_general_room_supports_normal_message_endpoints() -> None:
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        await _register(client, "generalfrank")
        room = (await client.post("/rooms/general/join", headers=_csrf(client))).json()

        send_response = await client.post(
            f"/rooms/{room['id']}/messages",
            json={"ciphertext": "general-cipher", "iv": "iv"},
            headers=_csrf(client),
        )
        assert send_response.status_code == 201

        history = (await client.get(f"/rooms/{room['id']}/messages")).json()
        assert history[-1]["ciphertext"] == "general-cipher"
