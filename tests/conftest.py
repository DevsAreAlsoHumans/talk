import base64
from uuid import uuid4

import fakeredis.aioredis
import pytest
from fastapi.testclient import TestClient

from app.config import Settings
from app.main import create_app

TEST_ORIGIN = "http://testserver"


@pytest.fixture
def redis_client():
    return fakeredis.aioredis.FakeRedis(
        server=fakeredis.FakeServer(),
        decode_responses=True,
    )


@pytest.fixture
def settings():
    return Settings(
        environment="test",
        redis_url="redis://unused/15",
        allowed_origins=TEST_ORIGIN,
        allowed_hosts="testserver",
        cookie_secure=False,
        registration_rate_limit=100,
        login_rate_limit=100,
        docs_enabled=False,
    )


@pytest.fixture
def app(settings, redis_client):
    return create_app(settings=settings, redis_client=redis_client)


@pytest.fixture
def client(app):
    with TestClient(app, base_url=TEST_ORIGIN) as test_client:
        yield test_client


def valid_public_jwk():
    modulus = base64.urlsafe_b64encode(b"\xc0" + (b"\xff" * 383)).rstrip(b"=").decode()
    exponent = base64.urlsafe_b64encode((65537).to_bytes(3, "big")).rstrip(b"=").decode()
    return {
        "kty": "RSA",
        "alg": "RSA-OAEP-256",
        "use": "enc",
        "n": modulus,
        "e": exponent,
        "ext": True,
        "key_ops": ["encrypt"],
    }


def identity_payload(device_name="Test device"):
    return {
        "key_id": str(uuid4()),
        "device_name": device_name,
        "public_key": valid_public_jwk(),
    }


def csrf_headers(client, token=None):
    if token is None:
        token = client.get("/api/auth/csrf").json()["csrf_token"]
    return {"X-CSRF-Token": token, "Origin": TEST_ORIGIN}


def register_user(
    client,
    username="alice",
    password="Mot de passe très sûr 2026!",
    include_response=False,
    origin=TEST_ORIGIN,
):
    csrf = client.get("/api/auth/csrf").json()["csrf_token"]
    response = client.post(
        "/api/auth/register",
        headers={"X-CSRF-Token": csrf, "Origin": origin},
        json={
            "username": username,
            "display_name": username.capitalize(),
            "password": password,
            "identity_key": identity_payload(),
        },
    )
    assert response.status_code == 201, response.text
    if include_response:
        return response.json(), response
    return response.json()


def key_envelope(user_result, key_version=1):
    key = user_result["identity_keys"][0]
    return {
        "recipient_id": user_result["user"]["id"],
        "key_id": key["key_id"],
        "algorithm": "RSA-OAEP-256",
        "wrapped_key": "A" * 512,
        "key_version": key_version,
    }


def create_room(client, members=(), name="Projet"):
    current_user = client.get("/api/auth/me").json()["user"]
    participants = list(members) or [current_user]
    envelopes = []
    invites = []
    for member in participants:
        if member["id"] != current_user["id"]:
            invites.append({"username": member["username"]})
        result = client.get(f"/api/users/{member['username']}/keys").json()
        envelopes.append(key_envelope(result))
    csrf = client.get("/api/auth/csrf").json()["csrf_token"]
    response = client.post(
        "/api/rooms",
        headers={"X-CSRF-Token": csrf, "Origin": TEST_ORIGIN},
        json={
            "name": name,
            "channel_name": "général",
            "invites": invites,
            "key_envelopes": envelopes,
        },
    )
    assert response.status_code == 201, response.text
    result = response.json()
    result["csrf_token"] = csrf
    return result


def encrypted_message(client_id=None, key_version=1):
    return {
        "client_id": client_id or str(uuid4()),
        "algorithm": "AES-GCM-256",
        "key_version": key_version,
        "ciphertext": base64.urlsafe_b64encode(b"encrypted-message" * 4).rstrip(b"=").decode(),
        "nonce": "A" * 16,
    }
