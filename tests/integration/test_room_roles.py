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


async def test_create_group_add_members_and_send_message() -> None:
    async with (
        AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as owner_client,
        AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as member_client,
    ):
        await _register(owner_client, "ownerr")
        member = await _register(member_client, "memberr")

        create_response = await owner_client.post(
            "/rooms/groups", json={"name": "Projet SDV"}, headers=_csrf(owner_client)
        )
        assert create_response.status_code == 201
        room = create_response.json()
        assert room["type"] == "group"
        assert room["members"][0]["role"] == "owner"
        room_id = room["id"]

        add_response = await owner_client.post(
            f"/rooms/{room_id}/members",
            json={"username": "memberr", "discriminator": member["discriminator"]},
            headers=_csrf(owner_client),
        )
        assert add_response.status_code == 200
        assert len(add_response.json()["members"]) == 2

        send_response = await member_client.post(
            f"/rooms/{room_id}/messages",
            json={"ciphertext": "group-cipher", "iv": "iv"},
            headers=_csrf(member_client),
        )
        assert send_response.status_code == 201

        history = await owner_client.get(f"/rooms/{room_id}/messages")
        assert history.json()[0]["ciphertext"] == "group-cipher"


async def test_member_cannot_add_or_remove_members() -> None:
    async with (
        AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as owner_client,
        AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as member_client,
        AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as outsider_client,
    ):
        await _register(owner_client, "ownerp")
        member = await _register(member_client, "memberp")
        outsider = await _register(outsider_client, "outsiderp")

        room_id = (
            await owner_client.post(
                "/rooms/groups", json={"name": "Groupe"}, headers=_csrf(owner_client)
            )
        ).json()["id"]
        await owner_client.post(
            f"/rooms/{room_id}/members",
            json={"username": "memberp", "discriminator": member["discriminator"]},
            headers=_csrf(owner_client),
        )

        forbidden_add = await member_client.post(
            f"/rooms/{room_id}/members",
            json={"username": "outsiderp", "discriminator": outsider["discriminator"]},
            headers=_csrf(member_client),
        )
        assert forbidden_add.status_code == 403

        forbidden_remove = await member_client.delete(
            f"/rooms/{room_id}/members/{outsider['id']}", headers=_csrf(member_client)
        )
        # L'outsider n'est pas membre : 403 attendu avant meme de checker son existence,
        # car le membre simple n'a pas le droit de retirer qui que ce soit.
        assert forbidden_remove.status_code in (403, 404)


async def test_owner_promotes_member_and_admin_can_then_add_members() -> None:
    async with (
        AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as owner_client,
        AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as member_client,
        AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as new_client,
    ):
        await _register(owner_client, "ownerq")
        member = await _register(member_client, "memberq")
        new_member = await _register(new_client, "newq")

        room_id = (
            await owner_client.post(
                "/rooms/groups", json={"name": "Groupe2"}, headers=_csrf(owner_client)
            )
        ).json()["id"]
        await owner_client.post(
            f"/rooms/{room_id}/members",
            json={"username": "memberq", "discriminator": member["discriminator"]},
            headers=_csrf(owner_client),
        )

        promote_response = await owner_client.patch(
            f"/rooms/{room_id}/members/{member['id']}",
            json={"role": "admin"},
            headers=_csrf(owner_client),
        )
        assert promote_response.status_code == 200

        add_response = await member_client.post(
            f"/rooms/{room_id}/members",
            json={"username": "newq", "discriminator": new_member["discriminator"]},
            headers=_csrf(member_client),
        )
        assert add_response.status_code == 200
        assert len(add_response.json()["members"]) == 3


async def test_owner_cannot_leave_and_admin_cannot_remove_owner() -> None:
    async with (
        AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as owner_client,
        AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as admin_client,
    ):
        owner = await _register(owner_client, "ownerz")
        admin = await _register(admin_client, "adminz")

        room_id = (
            await owner_client.post(
                "/rooms/groups", json={"name": "Groupe3"}, headers=_csrf(owner_client)
            )
        ).json()["id"]
        await owner_client.post(
            f"/rooms/{room_id}/members",
            json={"username": "adminz", "discriminator": admin["discriminator"]},
            headers=_csrf(owner_client),
        )
        await owner_client.patch(
            f"/rooms/{room_id}/members/{admin['id']}",
            json={"role": "admin"},
            headers=_csrf(owner_client),
        )

        leave_response = await owner_client.delete(
            f"/rooms/{room_id}/members/{owner['id']}", headers=_csrf(owner_client)
        )
        assert leave_response.status_code == 400

        remove_owner_response = await admin_client.delete(
            f"/rooms/{room_id}/members/{owner['id']}", headers=_csrf(admin_client)
        )
        assert remove_owner_response.status_code == 403
