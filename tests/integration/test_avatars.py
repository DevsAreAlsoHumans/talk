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


async def test_set_dicebear_avatar() -> None:
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        await _register(client, "avatar1")

        response = await client.put(
            "/users/me/avatar/dicebear", json={"seed": "my-seed"}, headers=_csrf(client)
        )

        assert response.status_code == 200
        avatar = response.json()["avatar"]
        assert avatar["type"] == "dicebear"
        assert avatar["value"] == "my-seed"
        assert "api.dicebear.com" in avatar["url"]


async def test_upload_avatar_and_fetch_it_back() -> None:
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        await _register(client, "avatar2")

        files = {"file": ("avatar.png", b"\x89PNG\r\n\x1a\n-fake-png-bytes-", "image/png")}
        upload_response = await client.post(
            "/users/me/avatar/upload", files=files, headers=_csrf(client)
        )
        assert upload_response.status_code == 200
        avatar = upload_response.json()["avatar"]
        assert avatar["type"] == "upload"
        assert avatar["url"].startswith("/users/avatars/")

        fetch_response = await client.get(avatar["url"])
        assert fetch_response.status_code == 200
        assert fetch_response.content == b"\x89PNG\r\n\x1a\n-fake-png-bytes-"


async def test_upload_avatar_rejects_wrong_content_type() -> None:
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        await _register(client, "avatar3")

        files = {"file": ("payload.exe", b"not-an-image", "application/octet-stream")}
        response = await client.post(
            "/users/me/avatar/upload", files=files, headers=_csrf(client)
        )

        assert response.status_code == 415


async def test_upload_avatar_rejects_oversized_file() -> None:
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        await _register(client, "avatar4")

        oversized = b"0" * (2 * 1024 * 1024 + 1)
        files = {"file": ("big.png", oversized, "image/png")}
        response = await client.post(
            "/users/me/avatar/upload", files=files, headers=_csrf(client)
        )

        assert response.status_code == 413


async def test_avatar_blob_id_path_traversal_is_rejected() -> None:
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        await _register(client, "avatar5")

        response = await client.get("/users/avatars/..%2F..%2Fapp%2Fmain.py")

        assert response.status_code == 404
