import uuid
from typing import Any

import pyotp
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


async def test_setup_confirm_and_login_with_totp() -> None:
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        user = await _register(client, "totp1")

        setup_response = await client.post("/auth/2fa/setup", headers=_csrf(client))
        assert setup_response.status_code == 200
        secret = setup_response.json()["secret"]

        confirm_response = await client.post(
            "/auth/2fa/confirm",
            json={"code": pyotp.TOTP(secret).now()},
            headers=_csrf(client),
        )
        assert confirm_response.status_code == 200
        assert confirm_response.json()["enabled"] is True

        await client.post("/auth/logout", headers=_csrf(client))

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client2:
        login_response = await client2.post(
            "/auth/login", json={"email": user["email"], "password": STRONG_PASSWORD}
        )
        assert login_response.status_code == 200
        body = login_response.json()
        assert body["totp_required"] is True
        pending_token = body["pending_token"]

        wrong_code_response = await client2.post(
            "/auth/2fa/verify", json={"pending_token": pending_token, "code": "000000"}
        )
        assert wrong_code_response.status_code == 401

        verify_response = await client2.post(
            "/auth/2fa/verify",
            json={"pending_token": pending_token, "code": pyotp.TOTP(secret).now()},
        )
        assert verify_response.status_code == 200
        assert verify_response.json()["email"] == user["email"]

        me_response = await client2.get("/auth/me")
        assert me_response.status_code == 200


async def test_confirm_with_wrong_code_does_not_enable_2fa() -> None:
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        user = await _register(client, "totp2")
        await client.post("/auth/2fa/setup", headers=_csrf(client))

        response = await client.post(
            "/auth/2fa/confirm", json={"code": "000000"}, headers=_csrf(client)
        )
        assert response.status_code == 400

        # Toujours pas de 2FA active : le prochain login ne doit pas la demander.
        login_response = await client.post(
            "/auth/login", json={"email": user["email"], "password": STRONG_PASSWORD}
        )
        assert login_response.json()["totp_required"] is False


async def test_disable_totp_requires_valid_code() -> None:
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        await _register(client, "totp3")
        setup_response = await client.post("/auth/2fa/setup", headers=_csrf(client))
        secret = setup_response.json()["secret"]
        await client.post(
            "/auth/2fa/confirm", json={"code": pyotp.TOTP(secret).now()}, headers=_csrf(client)
        )

        wrong_disable = await client.post(
            "/auth/2fa/disable", json={"code": "000000"}, headers=_csrf(client)
        )
        assert wrong_disable.status_code == 400

        good_disable = await client.post(
            "/auth/2fa/disable",
            json={"code": pyotp.TOTP(secret).now()},
            headers=_csrf(client),
        )
        assert good_disable.status_code == 200
        assert good_disable.json()["enabled"] is False
