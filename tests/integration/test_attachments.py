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


async def _create_dm(alice_client: AsyncClient, bob: dict[str, Any]) -> str:
    response = await alice_client.post(
        "/rooms/dm", json={"username": bob["username"], "discriminator": bob["discriminator"]}
    )
    return response.json()["id"]


async def test_upload_attach_to_message_and_download() -> None:
    async with (
        AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as alice_client,
        AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as bob_client,
    ):
        await _register(alice_client, "attachalice")
        bob = await _register(bob_client, "attachbob")
        room_id = await _create_dm(alice_client, bob)

        ciphertext_bytes = b"\x01\x02\x03-fake-encrypted-file-bytes-\x04\x05"
        upload_response = await alice_client.post(
            f"/rooms/{room_id}/attachments",
            data={"iv": "attachment-iv"},
            files={"file": ("blob", ciphertext_bytes, "application/octet-stream")},
            headers=_csrf(alice_client),
        )
        assert upload_response.status_code == 200
        attachment = upload_response.json()
        assert attachment["size"] == len(ciphertext_bytes)
        assert attachment["iv"] == "attachment-iv"

        message_response = await alice_client.post(
            f"/rooms/{room_id}/messages",
            json={"ciphertext": "caption-cipher", "iv": "iv", "attachment_id": attachment["id"]},
            headers=_csrf(alice_client),
        )
        assert message_response.status_code == 201
        assert message_response.json()["attachment"]["id"] == attachment["id"]

        history = (await bob_client.get(f"/rooms/{room_id}/messages")).json()
        assert history[0]["attachment"]["sha256"] == attachment["sha256"]

        download_response = await bob_client.get(
            f"/rooms/{room_id}/attachments/{attachment['id']}"
        )
        assert download_response.status_code == 200
        assert download_response.content == ciphertext_bytes


async def test_non_member_cannot_download_attachment() -> None:
    async with (
        AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as alice_client,
        AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as bob_client,
        AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as intruder_client,
    ):
        await _register(alice_client, "attachcarol")
        bob = await _register(bob_client, "attachdave")
        await _register(intruder_client, "attacheve")
        room_id = await _create_dm(alice_client, bob)

        upload_response = await alice_client.post(
            f"/rooms/{room_id}/attachments",
            data={"iv": "iv"},
            files={"file": ("blob", b"secret-bytes", "application/octet-stream")},
            headers=_csrf(alice_client),
        )
        attachment_id = upload_response.json()["id"]

        response = await intruder_client.get(f"/rooms/{room_id}/attachments/{attachment_id}")
        assert response.status_code == 404


async def test_upload_rejects_oversized_attachment() -> None:
    async with (
        AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as alice_client,
        AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as bob_client,
    ):
        await _register(alice_client, "attachfrank")
        bob = await _register(bob_client, "attachgina")
        room_id = await _create_dm(alice_client, bob)

        oversized = b"0" * (20 * 1024 * 1024 + 1)
        response = await alice_client.post(
            f"/rooms/{room_id}/attachments",
            data={"iv": "iv"},
            files={"file": ("blob", oversized, "application/octet-stream")},
            headers=_csrf(alice_client),
        )
        assert response.status_code == 413


async def test_cannot_reference_attachment_from_another_room() -> None:
    async with (
        AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as alice_client,
        AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as bob_client,
        AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as carol_client,
    ):
        await _register(alice_client, "attachharry")
        bob = await _register(bob_client, "attachivy")
        carol = await _register(carol_client, "attachjack")

        room_ab = await _create_dm(alice_client, bob)
        room_ac = await _create_dm(alice_client, carol)

        upload_response = await alice_client.post(
            f"/rooms/{room_ab}/attachments",
            data={"iv": "iv"},
            files={"file": ("blob", b"bytes-for-room-ab", "application/octet-stream")},
            headers=_csrf(alice_client),
        )
        attachment_id = upload_response.json()["id"]

        response = await alice_client.post(
            f"/rooms/{room_ac}/messages",
            json={"ciphertext": "c", "iv": "iv", "attachment_id": attachment_id},
            headers=_csrf(alice_client),
        )
        assert response.status_code == 400
