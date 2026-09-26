import uuid

import pytest
from httpx import ASGITransport, AsyncClient

from app.db.mongo import ensure_indexes
from app.main import app
from tests.integration.mailhog_helper import wait_for_mail

pytestmark = pytest.mark.asyncio(loop_scope="session")

STRONG_PASSWORD = "Sup3r$ecretPass!"
WRONG_PASSWORD = "WrongPass123!"


@pytest.fixture(autouse=True)
async def _prepare_indexes() -> None:
    await ensure_indexes()


def _unique_email() -> str:
    return f"user-{uuid.uuid4().hex}@example.com"


async def test_account_locks_after_three_failed_attempts_and_sends_alert() -> None:
    email = _unique_email()
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        register_response = await client.post(
            "/auth/register",
            json={"username": "bruteforce1", "email": email, "password": STRONG_PASSWORD},
        )
        assert register_response.status_code == 201

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        for _ in range(3):
            response = await client.post(
                "/auth/login", json={"email": email, "password": WRONG_PASSWORD}
            )
            assert response.status_code == 401

        locked_response = await client.post(
            "/auth/login", json={"email": email, "password": STRONG_PASSWORD}
        )
        assert locked_response.status_code == 423

        await wait_for_mail(email)


async def test_successful_login_resets_attempt_counter() -> None:
    email = _unique_email()
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        await client.post(
            "/auth/register",
            json={"username": "bruteforce2", "email": email, "password": STRONG_PASSWORD},
        )

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        for _ in range(2):
            await client.post("/auth/login", json={"email": email, "password": WRONG_PASSWORD})

        good_login = await client.post(
            "/auth/login", json={"email": email, "password": STRONG_PASSWORD}
        )
        assert good_login.status_code == 200

        # Le compteur a été remis à zéro : deux nouveaux échecs ne verrouillent pas.
        for _ in range(2):
            response = await client.post(
                "/auth/login", json={"email": email, "password": WRONG_PASSWORD}
            )
            assert response.status_code == 401

        still_unlocked = await client.post(
            "/auth/login", json={"email": email, "password": STRONG_PASSWORD}
        )
        assert still_unlocked.status_code == 200
