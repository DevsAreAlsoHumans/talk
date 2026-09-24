import uuid

from tests.conftest import auth_headers, csrf
from tests.crypto_helpers import (
    encrypt_message,
    new_keypair,
    public_key_jwk,
    wrap_channel_key,
)

import os


async def register_user(client, prefix):
    token = await csrf(client)
    username = prefix + "_" + uuid.uuid4().hex[:6]
    response = await client.post(
        "/api/auth/register",
        headers=auth_headers(token),
        json={
            "username": username,
            "email": username + "@test.fr",
            "password": "motdepasse123",
            "password_confirm": "motdepasse123",
        },
    )
    assert response.status_code == 201, response.text
    return response.json()


async def set_public_key(client, public_key):
    response = await client.put(
        "/api/me/public-key",
        headers=auth_headers(await csrf(client)),
        json={"public_key": public_key_jwk(public_key)},
    )
    assert response.status_code == 200, response.text


class TestAuth:
    async def test_me_requires_session(self, client):
        response = await client.get("/api/me")
        assert response.status_code == 401

    async def test_register_without_csrf_is_rejected(self, client):
        response = await client.post(
            "/api/auth/register",
            headers={"Content-Type": "application/json"},
            json={
                "username": "sanscsrf",
                "email": "sanscsrf@test.fr",
                "password": "motdepasse123",
                "password_confirm": "motdepasse123",
            },
        )
        assert response.status_code == 403

    async def test_register_with_bad_origin_is_rejected(self, client):
        token = await csrf(client)
        response = await client.post(
            "/api/auth/register",
            headers={
                "Content-Type": "application/json",
                "X-CSRF-Token": token,
                "Origin": "http://evil.example.com",
            },
            json={
                "username": "mauvaiseorth",
                "email": "mauvaiseorth@test.fr",
                "password": "motdepasse123",
                "password_confirm": "motdepasse123",
            },
        )
        assert response.status_code == 403

    async def test_register_then_me_and_duplicate(self, client):
        info = await register_user(client, "alice")
        assert "talk_session" in client.cookies

        me = await client.get("/api/me")
        assert me.status_code == 200
        assert me.json()["username"] == info["username"]

        duplicate = await client.post(
            "/api/auth/register",
            headers=auth_headers(await csrf(client)),
            json={
                "username": info["username"],
                "email": "autre@test.fr",
                "password": "motdepasse123",
                "password_confirm": "motdepasse123",
            },
        )
        assert duplicate.status_code == 409

    async def test_login_wrong_password(self, client):
        token = await csrf(client)
        wrong = await client.post(
            "/api/auth/login",
            headers=auth_headers(token),
            json={"username": "inconnu", "password": "motdepasse123"},
        )
        assert wrong.status_code == 401


class TestChatFlow:
    async def test_full_conversation_flow(self, make_client):
        alice = make_client()
        bob = make_client()
        intruder = make_client()

        alice_info = await register_user(alice, "alice")
        bob_info = await register_user(bob, "bob")
        alice_id = alice_info["id"]
        bob_id = bob_info["id"]

        _, alice_public_key = new_keypair()
        _, bob_public_key = new_keypair()
        await set_public_key(alice, alice_public_key)
        await set_public_key(bob, bob_public_key)

        search = await alice.get("/api/users/search?q=" + bob_info["username"])
        assert search.status_code == 200
        assert any(u["id"] == bob_id for u in search.json())

        pub = await alice.get("/api/users/" + bob_id + "/public-key")
        assert pub.status_code == 200
        assert pub.json()["public_key"]["kty"] == "RSA"

        aes_key = os.urandom(32)
        conversation = await alice.post(
            "/api/conversations",
            headers=auth_headers(await csrf(alice)),
            json={
                "user_id": bob_id,
                "key_wraps": {
                    alice_id: wrap_channel_key(aes_key, alice_public_key),
                    bob_id: wrap_channel_key(aes_key, bob_public_key),
                },
            },
        )
        assert conversation.status_code == 201, conversation.text
        conversation_id = conversation.json()["id"]

        secret = "message secret chiffre de bout en bout"
        encrypted = encrypt_message(secret.encode(), aes_key)
        sent = await alice.post(
            "/api/conversations/" + conversation_id + "/messages",
            headers=auth_headers(await csrf(alice)),
            json=encrypted,
        )
        assert sent.status_code == 201

        history = await alice.get(
            "/api/conversations/" + conversation_id + "/messages"
        )
        assert history.status_code == 200
        stored = history.json()
        assert len(stored) == 1
        assert stored[0]["iv"] == encrypted["iv"]
        assert stored[0]["ciphertext"] != secret
        assert secret not in stored[0]["ciphertext"]

        bob_convos = await bob.get("/api/conversations")
        assert bob_convos.status_code == 200
        assert any(c["id"] == conversation_id for c in bob_convos.json())

        bob_history = await bob.get(
            "/api/conversations/" + conversation_id + "/messages"
        )
        assert bob_history.status_code == 200
        assert bob_history.json()[0]["ciphertext"] != secret

        keys = await bob.get(
            "/api/conversations/" + conversation_id + "/keys"
        )
        assert keys.status_code == 200
        assert "wrapped" in keys.json()

        await register_user(intruder, "intrus")
        hidden = await intruder.get(
            "/api/conversations/" + conversation_id + "/messages"
        )
        assert hidden.status_code == 404

    async def test_same_pair_returns_existing_conversation(self, make_client):
        alice = make_client()
        bob = make_client()
        alice_info = await register_user(alice, "alice")
        bob_info = await register_user(bob, "bob")
        _, pub_a = new_keypair()
        _, pub_b = new_keypair()
        await set_public_key(alice, pub_a)
        await set_public_key(bob, pub_b)

        aes_key = os.urandom(32)
        payload = {
            "user_id": bob_info["id"],
            "key_wraps": {
                alice_info["id"]: wrap_channel_key(aes_key, pub_a),
                bob_info["id"]: wrap_channel_key(aes_key, pub_b),
            },
        }
        first = await alice.post(
            "/api/conversations",
            headers=auth_headers(await csrf(alice)),
            json=payload,
        )
        assert first.status_code == 201
        second = await alice.post(
            "/api/conversations",
            headers=auth_headers(await csrf(alice)),
            json=payload,
        )
        assert second.status_code == 201
        assert second.json()["created"] is False
        assert second.json()["id"] == first.json()["id"]