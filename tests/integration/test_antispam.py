"""Limitation de débit et champ-piège anti-spam."""

from app import ratelimit
from app.config import settings


async def test_honeypot_blocks_bot_signup(csrf_client, sample_user):
    payload = dict(sample_user, website="http://spam.example")
    response = await csrf_client.post("/auth/signup", json=payload)
    assert response.status_code == 400

    # Aucun compte ne doit avoir été créé.
    login = await csrf_client.post(
        "/auth/login",
        json={"username": sample_user["username"], "password": sample_user["password"]},
    )
    assert login.status_code == 401


async def test_empty_honeypot_lets_humans_through(csrf_client, sample_user):
    response = await csrf_client.post("/auth/signup", json=dict(sample_user, website=""))
    assert response.status_code == 201


async def test_login_brute_force_is_throttled(csrf_client, sample_user):
    await csrf_client.post("/auth/signup", json=sample_user)
    ratelimit.reset()

    bad = {"username": sample_user["username"], "password": "WrongPassword1"}
    for _ in range(settings.rate_limit_login):
        response = await csrf_client.post("/auth/login", json=bad)
        assert response.status_code == 401

    blocked = await csrf_client.post("/auth/login", json=bad)
    assert blocked.status_code == 429
    assert "Retry-After" in blocked.headers


async def test_throttling_also_blocks_the_correct_password(csrf_client, sample_user):
    """Une fois le quota épuisé, même les bonnes identifiants attendent."""
    await csrf_client.post("/auth/signup", json=sample_user)
    ratelimit.reset()

    bad = {"username": sample_user["username"], "password": "WrongPassword1"}
    for _ in range(settings.rate_limit_login):
        await csrf_client.post("/auth/login", json=bad)

    good = {"username": sample_user["username"], "password": sample_user["password"]}
    assert (await csrf_client.post("/auth/login", json=good)).status_code == 429


async def test_signup_flood_is_throttled(csrf_client):
    ratelimit.reset()
    for i in range(settings.rate_limit_signup):
        response = await csrf_client.post(
            "/auth/signup",
            json={
                "username": f"user{i}",
                "email": f"user{i}@example.com",
                "password": "StrongP@ss1",
                "public_key": "key",
            },
        )
        assert response.status_code == 201

    blocked = await csrf_client.post(
        "/auth/signup",
        json={
            "username": "flood",
            "email": "flood@example.com",
            "password": "StrongP@ss1",
            "public_key": "key",
        },
    )
    assert blocked.status_code == 429


async def test_message_flood_is_throttled(auth_headers, salon_id):
    ratelimit.reset()
    for _ in range(settings.rate_limit_message):
        response = await auth_headers.post(
            f"/salons/{salon_id}/messages",
            json={"ciphertext": "spam", "iv": "iv"},
        )
        assert response.status_code == 201

    blocked = await auth_headers.post(
        f"/salons/{salon_id}/messages",
        json={"ciphertext": "spam", "iv": "iv"},
    )
    assert blocked.status_code == 429
