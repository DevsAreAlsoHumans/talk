import uuid

import pytest
from httpx import ASGITransport, AsyncClient

from app.db.mongo import ensure_indexes
from app.main import app

# Les clients Mongo/Redis sont des singletons liés à la boucle asyncio de session.
pytestmark = pytest.mark.asyncio(loop_scope="session")

STRONG_PASSWORD = "Sup3r$ecretPass!"


@pytest.fixture(autouse=True)
async def _prepare_indexes() -> None:
    """Les tests s'appuient sur les index uniques (email, pseudo+discriminant)."""
    await ensure_indexes()


def _unique_email() -> str:
    return f"user-{uuid.uuid4().hex}@example.com"


async def test_register_login_me_logout_flow() -> None:
    email = _unique_email()

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        register_response = await client.post(
            "/auth/register",
            json={"username": "alice", "email": email, "password": STRONG_PASSWORD},
        )
        assert register_response.status_code == 201
        body = register_response.json()
        assert body["email"] == email
        assert body["discriminator"].isdigit()

        me_response = await client.get("/auth/me")
        assert me_response.status_code == 200
        assert me_response.json()["email"] == email

        csrf_token = client.cookies.get("csrf_token")
        logout_response = await client.post("/auth/logout", headers={"X-CSRF-Token": csrf_token})
        assert logout_response.status_code == 204

        me_after_logout = await client.get("/auth/me")
        assert me_after_logout.status_code == 401


async def test_logout_without_csrf_token_is_rejected() -> None:
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        await client.post(
            "/auth/register",
            json={"username": "frank", "email": _unique_email(), "password": STRONG_PASSWORD},
        )

        response = await client.post("/auth/logout")

        assert response.status_code == 403


async def test_register_duplicate_email_returns_409() -> None:
    email = _unique_email()

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        first = await client.post(
            "/auth/register",
            json={"username": "bob", "email": email, "password": STRONG_PASSWORD},
        )
        assert first.status_code == 201

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        second = await client.post(
            "/auth/register",
            json={"username": "bobby", "email": email, "password": STRONG_PASSWORD},
        )
        assert second.status_code == 409


async def test_register_weak_password_returns_422() -> None:
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await client.post(
            "/auth/register",
            json={"username": "carol", "email": _unique_email(), "password": "weak"},
        )

        assert response.status_code == 422


async def test_login_wrong_password_returns_401() -> None:
    email = _unique_email()

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        await client.post(
            "/auth/register",
            json={"username": "dave", "email": email, "password": STRONG_PASSWORD},
        )

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await client.post(
            "/auth/login", json={"email": email, "password": "WrongPass123!"}
        )

        assert response.status_code == 401


async def test_login_with_correct_credentials_returns_200() -> None:
    email = _unique_email()

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        await client.post(
            "/auth/register",
            json={"username": "erin", "email": email, "password": STRONG_PASSWORD},
        )

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await client.post(
            "/auth/login", json={"email": email, "password": STRONG_PASSWORD}
        )

        assert response.status_code == 200
        assert response.json()["email"] == email
