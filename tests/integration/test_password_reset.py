import quopri
import uuid

import pytest
from httpx import ASGITransport, AsyncClient

from app.db.mongo import ensure_indexes
from app.main import app
from tests.integration.mailhog_helper import wait_for_mail

pytestmark = pytest.mark.asyncio(loop_scope="session")

STRONG_PASSWORD = "Sup3r$ecretPass!"
NEW_PASSWORD = "Nouveau$ecret456!"


@pytest.fixture(autouse=True)
async def _prepare_indexes() -> None:
    await ensure_indexes()


def _unique_email() -> str:
    return f"user-{uuid.uuid4().hex}@example.com"


def _extract_token(mail_body: str) -> str:
    """Le corps du mail peut être encodé quoted-printable (Mailhog le renvoie tel quel)."""
    decoded = quopri.decodestring(mail_body.encode()).decode()
    return decoded.strip().split(":")[-1].strip()


async def test_forgot_and_reset_password_flow() -> None:
    email = _unique_email()
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        register_response = await client.post(
            "/auth/register",
            json={"username": "resetuser", "email": email, "password": STRONG_PASSWORD},
        )
        assert register_response.status_code == 201

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        forgot_response = await client.post("/auth/forgot-password", json={"email": email})
        assert forgot_response.status_code == 202

        message = await wait_for_mail(email)
        token = _extract_token(message["Content"]["Body"])

        reset_response = await client.post(
            "/auth/reset-password", json={"token": token, "new_password": NEW_PASSWORD}
        )
        assert reset_response.status_code == 200

        # Le jeton est à usage unique.
        reuse_response = await client.post(
            "/auth/reset-password", json={"token": token, "new_password": NEW_PASSWORD}
        )
        assert reuse_response.status_code == 400

        login_old = await client.post(
            "/auth/login", json={"email": email, "password": STRONG_PASSWORD}
        )
        assert login_old.status_code == 401

        login_new = await client.post(
            "/auth/login", json={"email": email, "password": NEW_PASSWORD}
        )
        assert login_new.status_code == 200
        assert login_new.json()["totp_required"] is False


async def test_forgot_password_unknown_email_still_returns_202() -> None:
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await client.post(
            "/auth/forgot-password", json={"email": "inconnu-" + _unique_email()}
        )
        assert response.status_code == 202


async def test_reset_password_with_invalid_token_returns_400() -> None:
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await client.post(
            "/auth/reset-password",
            json={"token": "not-a-real-token", "new_password": NEW_PASSWORD},
        )
        assert response.status_code == 400


async def test_reset_password_rejects_weak_password() -> None:
    email = _unique_email()
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        await client.post(
            "/auth/register",
            json={"username": "weakresetuser", "email": email, "password": STRONG_PASSWORD},
        )

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        await client.post("/auth/forgot-password", json={"email": email})
        message = await wait_for_mail(email)
        token = _extract_token(message["Content"]["Body"])

        response = await client.post(
            "/auth/reset-password", json={"token": token, "new_password": "weak"}
        )
        assert response.status_code == 422
