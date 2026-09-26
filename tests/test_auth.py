"""Inscription, connexion, déconnexion et cycle de vie des sessions."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from fastapi.testclient import TestClient

from app.config import CSRF_COOKIE_NAME, SESSION_COOKIE_NAME, get_settings
from tests.conftest import (
    VALID_PASSWORD,
    csrf_headers,
    register_user,
    session_cookie,
    sync_database,
    unique_username,
)


def test_register_creates_user_and_opens_session(client: TestClient) -> None:
    username = unique_username()

    response = client.post(
        "/auth/register",
        json={"username": username, "password": VALID_PASSWORD},
        headers=csrf_headers(client),
    )

    assert response.status_code == 201
    body = response.json()
    assert body["username"] == username
    assert body["id"]
    # Aucune trace du secret ne doit sortir de l'API.
    assert "password" not in body
    assert "password_hash" not in body
    assert session_cookie(client) is not None


def test_register_rejects_duplicate_username(client: TestClient) -> None:
    username = register_user(client)

    response = client.post(
        "/auth/register",
        json={"username": username, "password": VALID_PASSWORD},
        headers=csrf_headers(client),
    )

    assert response.status_code == 409


def test_register_username_is_case_insensitive(client: TestClient) -> None:
    username = register_user(client)

    response = client.post(
        "/auth/register",
        json={"username": username.upper(), "password": VALID_PASSWORD},
        headers=csrf_headers(client),
    )

    assert response.status_code == 409


@pytest.mark.parametrize("username", ["ab", "x" * 33, "avec espace", "symbole!"])
def test_register_rejects_invalid_username(client: TestClient, username: str) -> None:
    response = client.post(
        "/auth/register",
        json={"username": username, "password": VALID_PASSWORD},
        headers=csrf_headers(client),
    )

    assert response.status_code == 422


@pytest.mark.parametrize("password", ["court", "a" * 300])
def test_register_rejects_invalid_password(client: TestClient, password: str) -> None:
    response = client.post(
        "/auth/register",
        json={"username": unique_username(), "password": password},
        headers=csrf_headers(client),
    )

    assert response.status_code == 422


def test_register_rejects_unknown_field(client: TestClient) -> None:
    response = client.post(
        "/auth/register",
        json={
            "username": unique_username(),
            "password": VALID_PASSWORD,
            "role": "admin",
        },
        headers=csrf_headers(client),
    )

    assert response.status_code == 422


def test_login_opens_session(client: TestClient) -> None:
    username = register_user(client)
    client.post("/auth/logout", headers=csrf_headers(client))

    response = client.post(
        "/auth/login",
        json={"username": username, "password": VALID_PASSWORD},
        headers=csrf_headers(client),
    )

    assert response.status_code == 200
    assert response.json()["username"] == username
    assert session_cookie(client) is not None
    assert client.get("/auth/me").status_code == 200


def test_login_with_wrong_password_is_rejected(client: TestClient) -> None:
    username = register_user(client)
    client.post("/auth/logout", headers=csrf_headers(client))

    response = client.post(
        "/auth/login",
        json={"username": username, "password": "mauvais-mot-de-passe"},
        headers=csrf_headers(client),
    )

    assert response.status_code == 401


def test_login_unknown_user_and_wrong_password_are_indistinguishable(
    client: TestClient,
) -> None:
    """Aucun énumérateur ne doit distinguer les deux cas."""
    username = register_user(client)
    client.post("/auth/logout", headers=csrf_headers(client))

    unknown = client.post(
        "/auth/login",
        json={"username": unique_username("absent"), "password": VALID_PASSWORD},
        headers=csrf_headers(client),
    )
    wrong = client.post(
        "/auth/login",
        json={"username": username, "password": "mauvais-mot-de-passe"},
        headers=csrf_headers(client),
    )

    assert unknown.status_code == wrong.status_code == 401
    assert unknown.json() == wrong.json()


def test_login_rotates_session_token(client: TestClient) -> None:
    username = register_user(client)
    client.post("/auth/logout", headers=csrf_headers(client))
    client.get("/auth/csrf")
    before = session_cookie(client)

    client.post(
        "/auth/login",
        json={"username": username, "password": VALID_PASSWORD},
        headers=csrf_headers(client),
    )

    assert session_cookie(client) != before


def test_login_rotates_csrf_token(client: TestClient) -> None:
    username = register_user(client)
    client.post("/auth/logout", headers=csrf_headers(client))
    client.get("/auth/csrf")
    before = client.cookies.get(CSRF_COOKIE_NAME)

    client.post(
        "/auth/login",
        json={"username": username, "password": VALID_PASSWORD},
        headers=csrf_headers(client),
    )

    assert client.cookies.get(CSRF_COOKIE_NAME) != before


def test_previous_session_is_invalid_after_login(client: TestClient) -> None:
    """La rotation doit rendre l'ancien cookie inutilisable."""
    username = register_user(client)
    client.post("/auth/logout", headers=csrf_headers(client))
    client.get("/auth/csrf")
    stale = session_cookie(client)
    client.post(
        "/auth/login",
        json={"username": username, "password": VALID_PASSWORD},
        headers=csrf_headers(client),
    )

    client.cookies.set(SESSION_COOKIE_NAME, stale or "")
    assert client.get("/auth/me").status_code == 401


def test_logout_clears_cookies_and_session(client: TestClient) -> None:
    register_user(client)
    token = session_cookie(client)
    assert token is not None

    response = client.post("/auth/logout", headers=csrf_headers(client))

    assert response.status_code == 204
    assert not session_cookie(client)
    assert not client.cookies.get(CSRF_COOKIE_NAME)
    assert client.get("/auth/me").status_code == 401

    mongo = sync_database()
    try:
        database = mongo[get_settings().mongo_db_name]
        assert database.sessions.count_documents({}) == 0
    finally:
        mongo.close()


def test_me_requires_a_session(client: TestClient) -> None:
    assert client.get("/auth/me").status_code == 401


def test_me_returns_the_current_user(client: TestClient) -> None:
    username = register_user(client)

    response = client.get("/auth/me")

    assert response.status_code == 200
    assert response.json()["username"] == username


def test_expired_session_is_rejected(client: TestClient) -> None:
    """L'expiration est vérifiée en base, indépendamment du moniteur TTL."""
    register_user(client)
    mongo = sync_database()
    try:
        database = mongo[get_settings().mongo_db_name]
        database.sessions.update_many(
            {},
            {"$set": {"expires_at": datetime.now(UTC) - timedelta(minutes=1)}},
        )
    finally:
        mongo.close()

    assert client.get("/auth/me").status_code == 401


def test_rate_limit_blocks_repeated_failures(client: TestClient) -> None:
    username = register_user(client)
    client.post("/auth/logout", headers=csrf_headers(client))

    statuses = [
        client.post(
            "/auth/login",
            json={"username": username, "password": "mauvais-mot-de-passe"},
            headers=csrf_headers(client),
        ).status_code
        for _ in range(7)
    ]

    assert 429 in statuses
    assert statuses[-1] == 429
