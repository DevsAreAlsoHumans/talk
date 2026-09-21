"""Parcours d'authentification : inscription, connexion, déconnexion,
``/api/me``, rotation de session (anti-fixation), doublon 409, mauvais
mot de passe 401 et rate-limit 429 après répétition d'échecs.
"""

from __future__ import annotations

from tests.helpers.crypto_client import (
    csrf_headers,
    default_public_key,
    fetch_csrf,
    login,
    register,
)


async def test_register_returns_public_user_and_csrf(client) -> None:
    data = await register(client, "alice_r", "password123")
    user = data["user"]
    assert set(user) == {
        "id",
        "username",
        "public_key",
        "created_at",
        "display_name",
        "about",
    }
    assert user["display_name"] is None and user["about"] is None
    assert data["csrf_token"]
    # Le mot de passe ne transite jamais dans la réponse.
    assert "password123" not in repr(data)
    assert "password" not in user


async def test_register_sets_session_cookie(client) -> None:
    await register(client, "alice_ck", "password123")
    assert client.cookies.get("session") is not None


async def test_duplicate_username_returns_409(client) -> None:
    await register(client, "alice_dup", "password123")
    csrf_token = await fetch_csrf(client)
    response = await client.post(
        "/api/auth/register",
        json={
            "username": "alice_dup",
            "password": "password123",
            "public_key": default_public_key(),
        },
        headers=csrf_headers(csrf_token),
    )
    assert response.status_code == 409
    assert response.json() == {"detail": "Username already taken"}


async def test_me_requires_authentication(client) -> None:
    response = await client.get("/api/me")
    assert response.status_code == 401
    assert response.json() == {"detail": "Authentication required"}


async def test_register_then_me_shows_profile_and_empty_rooms(client) -> None:
    data = await register(client, "alice_me", "password123")
    response = await client.get("/api/me")
    assert response.status_code == 200
    body = response.json()
    assert body["user"]["id"] == data["user"]["id"]
    assert body["rooms"] == []


async def test_logout_invalidates_session_and_cookie(client) -> None:
    await register(client, "alice_lo", "password123")
    csrf_token = await fetch_csrf(client)
    response = await client.post("/api/auth/logout", headers=csrf_headers(csrf_token))
    assert response.status_code == 204
    assert client.cookies.get("session") is None
    assert (await client.get("/api/me")).status_code == 401

    await login(client, "alice_lo", "password123")
    assert (await client.get("/api/me")).status_code == 200


async def test_login_with_wrong_password_returns_401(client) -> None:
    await register(client, "alice_wp", "password123")
    csrf_token = await fetch_csrf(client)
    response = await client.post(
        "/api/auth/login",
        json={"username": "alice_wp", "password": "incorrect"},
        headers=csrf_headers(csrf_token),
    )
    assert response.status_code == 401
    assert response.json() == {"detail": "Invalid credentials"}


async def test_session_rotation_invalidates_previous_cookie(make_client, client) -> None:
    await fetch_csrf(client)  # session anonyme
    old_sid = client.cookies.get("session")
    await register(client, "alice_rot", "password123")
    new_sid = client.cookies.get("session")
    assert old_sid != new_sid

    async with make_client() as stale_client:
        stale_client.cookies.set("session", old_sid)
        assert (await stale_client.get("/api/me")).status_code == 401

    assert (await client.get("/api/me")).status_code == 200


async def test_login_rotates_session(make_client, client) -> None:
    await register(client, "alice_lr", "password123")
    await fetch_csrf(client)
    before = client.cookies.get("session")
    await login(client, "alice_lr", "password123")
    after = client.cookies.get("session")
    assert before != after

    async with make_client() as stale_client:
        stale_client.cookies.set("session", before)
        assert (await stale_client.get("/api/me")).status_code == 401


async def test_rate_limit_blocks_after_repeated_failures(redis, client) -> None:
    await register(client, "alice_rl", "password123")  # 1ère tentative comptée
    csrf_token = await fetch_csrf(client)

    for _ in range(9):
        response = await client.post(
            "/api/auth/login",
            json={"username": "alice_rl", "password": "incorrect"},
            headers=csrf_headers(csrf_token),
        )
        assert response.status_code == 401

    # 10e échec → blocage (10 échecs cumulés + enregistrement).
    for _ in range(2):
        response = await client.post(
            "/api/auth/login",
            json={"username": "alice_rl", "password": "incorrect"},
            headers=csrf_headers(csrf_token),
        )
        assert response.status_code == 429

    # Après blocage, le bon mot de passe est aussi refusé (pas d'oracle).
    response = await client.post(
        "/api/auth/login",
        json={"username": "alice_rl", "password": "password123"},
        headers=csrf_headers(csrf_token),
    )
    assert response.status_code == 429


async def test_successful_login_resets_rate_limit(redis, client) -> None:
    await register(client, "alice_rs", "password123")
    csrf_token = await fetch_csrf(client)
    for _ in range(3):
        await client.post(
            "/api/auth/login",
            json={"username": "alice_rs", "password": "incorrect"},
            headers=csrf_headers(csrf_token),
        )

    await login(client, "alice_rs", "password123")
    # Le compteur a été réinitialisé (l'IP est "unknown" avec ASGITransport).
    assert redis.get("rl:login:unknown:alice_rs") is None

    csrf_token = await fetch_csrf(client)
    for _ in range(10):
        response = await client.post(
            "/api/auth/login",
            json={"username": "alice_rs", "password": "incorrect"},
            headers=csrf_headers(csrf_token),
        )
        assert response.status_code == 401
    response = await client.post(
        "/api/auth/login",
        json={"username": "alice_rs", "password": "incorrect"},
        headers=csrf_headers(csrf_token),
    )
    assert response.status_code == 429
