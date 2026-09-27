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


async def test_initial_rotation_and_list_keys() -> None:
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as owner:
        user = await _register(owner, "keyowner1")
        room = (
            await owner.post("/rooms/groups", json={"name": "Groupe clé"}, headers=_csrf(owner))
        ).json()
        assert room["key_epoch"] == 0

        rotate_response = await owner.post(
            f"/rooms/{room['id']}/keys",
            json={
                "wrapper_public_key": "owner-pubkey",
                "entries": [
                    {"member_id": user["id"], "wrapped_key": "wrapped", "wrapped_key_iv": "iv"}
                ],
            },
            headers=_csrf(owner),
        )
        assert rotate_response.status_code == 200
        assert rotate_response.json()["key_epoch"] == 1

        keys_response = await owner.get(f"/rooms/{room['id']}/keys")
        assert keys_response.status_code == 200
        keys = keys_response.json()
        assert len(keys) == 1
        assert keys[0]["epoch"] == 1
        assert keys[0]["wrapper_public_key"] == "owner-pubkey"


async def test_rotation_must_cover_exact_current_members() -> None:
    async with (
        AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as owner,
        AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as member,
    ):
        owner_user = await _register(owner, "keyowner2")
        member_user = await _register(member, "keymember2")

        room = (
            await owner.post("/rooms/groups", json={"name": "Groupe clé 2"}, headers=_csrf(owner))
        ).json()
        await owner.post(
            f"/rooms/{room['id']}/members",
            json={"username": "keymember2", "discriminator": member_user["discriminator"]},
            headers=_csrf(owner),
        )

        incomplete_response = await owner.post(
            f"/rooms/{room['id']}/keys",
            json={
                "wrapper_public_key": "owner-pubkey",
                "entries": [
                    {
                        "member_id": owner_user["id"],
                        "wrapped_key": "wrapped",
                        "wrapped_key_iv": "iv",
                    }
                ],
            },
            headers=_csrf(owner),
        )
        assert incomplete_response.status_code == 400

        complete_response = await owner.post(
            f"/rooms/{room['id']}/keys",
            json={
                "wrapper_public_key": "owner-pubkey",
                "entries": [
                    {
                        "member_id": owner_user["id"],
                        "wrapped_key": "wrapped-owner",
                        "wrapped_key_iv": "iv",
                    },
                    {
                        "member_id": member_user["id"],
                        "wrapped_key": "wrapped-member",
                        "wrapped_key_iv": "iv",
                    },
                ],
            },
            headers=_csrf(owner),
        )
        assert complete_response.status_code == 200
        assert complete_response.json()["key_epoch"] == 1


async def test_plain_member_can_rotate_key() -> None:
    """Un simple membre peut faire tourner la clé lui-même (ex: nouvel arrivant
    sur #général qui n'a pas encore d'accès admin) — seule la composition
    exacte des membres est vérifiée, pas le rôle de l'auteur de la rotation."""
    async with (
        AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as owner,
        AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as member,
    ):
        owner_user = await _register(owner, "keyowner3")
        member_user = await _register(member, "keymember3")

        room = (
            await owner.post("/rooms/groups", json={"name": "Groupe clé 3"}, headers=_csrf(owner))
        ).json()
        await owner.post(
            f"/rooms/{room['id']}/members",
            json={"username": "keymember3", "discriminator": member_user["discriminator"]},
            headers=_csrf(owner),
        )

        response = await member.post(
            f"/rooms/{room['id']}/keys",
            json={
                "wrapper_public_key": "member-pubkey",
                "entries": [
                    {
                        "member_id": owner_user["id"],
                        "wrapped_key": "wrapped-owner",
                        "wrapped_key_iv": "iv",
                    },
                    {
                        "member_id": member_user["id"],
                        "wrapped_key": "wrapped-member",
                        "wrapped_key_iv": "iv",
                    },
                ],
            },
            headers=_csrf(member),
        )
        assert response.status_code == 200
        assert response.json()["key_epoch"] == 1


async def test_non_member_cannot_rotate_key() -> None:
    async with (
        AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as owner,
        AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as outsider,
    ):
        owner_user = await _register(owner, "keyowner3b")
        await _register(outsider, "keyoutsider3b")

        room = (
            await owner.post("/rooms/groups", json={"name": "Groupe clé 3b"}, headers=_csrf(owner))
        ).json()

        response = await outsider.post(
            f"/rooms/{room['id']}/keys",
            json={
                "wrapper_public_key": "outsider-pubkey",
                "entries": [
                    {
                        "member_id": owner_user["id"],
                        "wrapped_key": "wrapped",
                        "wrapped_key_iv": "iv",
                    }
                ],
            },
            headers=_csrf(outsider),
        )
        assert response.status_code == 404


async def test_removed_member_cannot_list_group_keys() -> None:
    async with (
        AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as owner,
        AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as member,
    ):
        owner_user = await _register(owner, "keyowner4")
        member_user = await _register(member, "keymember4")

        room = (
            await owner.post("/rooms/groups", json={"name": "Groupe clé 4"}, headers=_csrf(owner))
        ).json()
        await owner.post(
            f"/rooms/{room['id']}/members",
            json={"username": "keymember4", "discriminator": member_user["discriminator"]},
            headers=_csrf(owner),
        )
        await owner.post(
            f"/rooms/{room['id']}/keys",
            json={
                "wrapper_public_key": "owner-pubkey",
                "entries": [
                    {
                        "member_id": owner_user["id"],
                        "wrapped_key": "wrapped-owner",
                        "wrapped_key_iv": "iv",
                    },
                    {
                        "member_id": member_user["id"],
                        "wrapped_key": "wrapped-member",
                        "wrapped_key_iv": "iv",
                    },
                ],
            },
            headers=_csrf(owner),
        )

        assert (await member.get(f"/rooms/{room['id']}/keys")).status_code == 200

        await owner.delete(
            f"/rooms/{room['id']}/members/{member_user['id']}", headers=_csrf(owner)
        )

        assert (await member.get(f"/rooms/{room['id']}/keys")).status_code == 404
