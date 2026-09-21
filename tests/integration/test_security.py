"""Cas sécurité : mutations sans CSRF → 403, rejet des « injections »
(username), aucun texte clair stocké dans Redis, erreurs 500 génériques
(sans stack trace), cookies HttpOnly/SameSite et headers de sécurité HTTP.
"""

from __future__ import annotations

import base64
import uuid

import httpx
import pytest
from fastapi import FastAPI
from starlette.websockets import WebSocketDisconnect

from tests.helpers.crypto_client import (
    ORIGIN,
    create_room,
    csrf_headers,
    default_public_key,
    encrypt_message,
    fetch_csrf,
    generate_room_key,
    register,
    wrap_key,
)

PASSWORD = "S3cret-!pass"


class _ExplodingRedis:
    """Simule une panne Redis : toute opération lève une exception interne."""

    def __getattr__(self, name: str):
        raise RuntimeError(f"exploded {name}")


class _BrokenPingRedis:
    """Simule un serveur Redis injoignable (le ping échoue)."""

    def ping(self) -> None:
        raise ConnectionError("redis down")


def _all_stored_values(redis) -> list[str]:
    """Toutes les valeurs (strings, hashs, sets…) stockées dans le Redis fake."""
    values: list[str] = []
    for key in redis.scan_iter():
        key_type = redis.type(key)
        if key_type == "string":
            values.append(redis.get(key) or "")
        elif key_type == "hash":
            values.extend(redis.hgetall(key).values())
        elif key_type == "set":
            values.extend(redis.smembers(key))
        elif key_type == "zset":
            values.extend(redis.zrange(key, 0, -1))
    return values


async def test_auth_mutations_require_csrf(client) -> None:
    """register/login/logout sans token CSRF → 403."""
    headers_without_token = {"origin": ORIGIN}
    response = await client.post(
        "/api/auth/register",
        json={
            "username": "sec_r",
            "password": PASSWORD,
            "public_key": default_public_key(),
        },
        headers=headers_without_token,
    )
    assert response.status_code == 403

    response = await client.post(
        "/api/auth/login",
        json={"username": "sec_r", "password": PASSWORD},
        headers=headers_without_token,
    )
    assert response.status_code == 403

    response = await client.post("/api/auth/logout", headers=headers_without_token)
    assert response.status_code == 403


async def test_room_mutations_require_csrf(client) -> None:
    data = await register(client, "sec_room", PASSWORD)
    room = await create_room(client, "general", data["csrf_token"])

    response = await client.post("/api/rooms", json={"name": "nono"}, headers={"origin": ORIGIN})
    assert response.status_code == 403
    response = await client.post(f"/api/rooms/{room['id']}/join", headers={"origin": ORIGIN})
    assert response.status_code == 403


@pytest.mark.parametrize(
    "username",
    ["al*ce", "a[0]", "a{1}", "admin$", "a b", "a\nb", "a;b", "alice`id", "al'ce"],
)
async def test_username_injection_rejected_and_not_stored(redis, client, username: str) -> None:
    """Les usernames « injection » sont rejetés par la validation (422) et
    aucune clé Redis n'est créée à partir de cette entrée."""
    csrf_token = await fetch_csrf(client)
    response = await client.post(
        "/api/auth/register",
        json={"username": username, "password": PASSWORD, "public_key": default_public_key()},
        headers=csrf_headers(csrf_token),
    )
    assert response.status_code == 422, response.text
    assert username not in list(redis.scan_iter())


async def test_password_never_stored_in_plain(redis, client) -> None:
    await register(client, "sec_pwd", "K3ep-This-Secret!")
    values = _all_stored_values(redis)
    assert not any("K3ep-This-Secret!" in value for value in values)
    # Le hash Argon2id est bien stocké.
    stored = "".join(values)
    assert "$argon2id$" in stored


async def test_no_plaintext_stored_in_redis(redis, client) -> None:
    """Preuve « jamais de clair côté serveur » : après un échange E2E complet
    via l'API, aucune valeur Redis ne contient le message d'origine."""
    data = await register(client, "sec_alice", PASSWORD)
    csrf = data["csrf_token"]
    room = await create_room(client, "covert", csrf)
    room_id = room["id"]

    # Clé de salon générée côté « navigateur » et enveloppée pour Alice.
    room_key = generate_room_key()
    wrapped = wrap_key(data["user"]["public_key"], room_key)
    response = await client.post(
        f"/api/rooms/{room_id}/keys",
        json={"target_user_id": data["user"]["id"], "wrapped_key": wrapped},
        headers=csrf_headers(csrf),
    )
    assert response.status_code == 201

    # Message chiffré (AES-256-GCM) : seule la paire nonce/ciphertext part.
    secret = f"TOPSECRET-{uuid.uuid4().hex}"
    nonce, ciphertext = encrypt_message(room_key, secret)
    response = await client.post(
        f"/api/rooms/{room_id}/messages",
        json={"nonce": nonce, "ciphertext": ciphertext},
        headers=csrf_headers(csrf),
    )
    assert response.status_code == 201
    message_id = response.json()["message"]["id"]

    # Le texte clair n'existe dans AUCUNE valeur stockée (ni la clé en clair).
    values = _all_stored_values(redis)
    assert not any(secret in value for value in values)
    assert not any(base64.b64encode(room_key).decode() in value for value in values)
    assert wrapped not in {ciphertext, base64.b64encode(room_key).decode()}

    # Le message stocké ne contient que du chiffré, pas le texte en clair.
    stored = redis.hgetall(f"message:{message_id}")
    assert stored["nonce"] == nonce
    assert stored["ciphertext"] == ciphertext


async def test_generic_500_does_not_leak_stack_trace(app: FastAPI) -> None:
    """Erreur interne (middleware) → 500 générique JSON, sans stack trace.

    ``Starlette`` relaie toujours l'exception après avoir envoyé le 500
    (pour le logging serveur) : on désactive donc ``raise_app_exceptions``.
    """
    transport = httpx.ASGITransport(app=app, raise_app_exceptions=False)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        data = await register(client, "sec_ok", PASSWORD)
        app.state.redis = _ExplodingRedis()
        response = await client.post(
            "/api/auth/register",
            json={"username": "sec_boom", "password": PASSWORD, "public_key": default_public_key()},
            headers=csrf_headers(data["csrf_token"]),
        )
    assert response.status_code == 500
    assert response.json() == {"detail": "Internal server error"}
    assert "Traceback" not in response.text
    assert "exploded" not in response.text


async def test_health_500_when_redis_unavailable(app: FastAPI, client) -> None:
    app.state.redis = _BrokenPingRedis()
    response = await client.get("/api/health")
    assert response.status_code == 500
    assert response.json() == {"detail": "Redis unavailable"}
    assert "Traceback" not in response.text


async def test_session_cookie_flags(client) -> None:
    csrf_token = await fetch_csrf(client)
    response = await client.post(
        "/api/auth/register",
        json={"username": "sec_flag", "password": PASSWORD, "public_key": default_public_key()},
        headers=csrf_headers(csrf_token),
    )
    assert response.status_code == 201
    set_cookie = response.headers.get("set-cookie")
    assert set_cookie is not None
    assert set_cookie.startswith("session=")
    assert "HttpOnly" in set_cookie
    assert "samesite=lax" in set_cookie.lower()
    assert "path=/" in set_cookie.lower()
    assert "max-age=604800" in set_cookie.lower()
    assert "secure" not in set_cookie.lower()  # développement (COOKIE_SECURE=False)


async def test_session_cookie_signature_tampering_rejected(make_client, client) -> None:
    """Le cookie de session est signé HMAC : toute altération est rejetée."""
    await fetch_csrf(client)
    await register(client, "sec_tamp", "password123")
    signed = client.cookies.get("session")
    assert signed is not None and "." in signed  # sid.signature

    # Un attaquant altère un caractère du sid (ou de la signature).
    tampered = ("A" if signed[0] != "A" else "B") + signed[1:]

    async with make_client() as forged_client:
        forged_client.cookies.set("session", tampered)
        assert (await forged_client.get("/api/me")).status_code == 401

    # Session légitime : toujours active.
    assert (await client.get("/api/me")).status_code == 200


async def test_security_headers_present(client) -> None:
    """Headers de protection sur toutes les réponses (même les erreurs)."""
    response = await client.get("/api/me")  # 401, mais les headers sont posés
    assert response.status_code == 401
    assert response.headers["content-security-policy"].startswith("default-src 'self'")
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["referrer-policy"] == "no-referrer"
    assert response.headers["x-xss-protection"] == "0"
    assert "strict-transport-security" not in response.headers


def test_websocket_unauthenticated_rejected(testclient) -> None:
    """La connexion WS sans session valide est fermée (code 4401)."""
    with pytest.raises(WebSocketDisconnect) as excinfo, testclient.websocket_connect("/ws"):
        pass
    assert excinfo.value.code == 4401
