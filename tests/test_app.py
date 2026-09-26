import os
import uuid

from app.config import settings
from tests.conftest import auth_headers, csrf
from tests.crypto_helpers import (
    encrypt_message,
    new_keypair,
    public_key_jwk,
    unwrap_channel_key,
    wrap_channel_key,
)


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


class TestSecurityHeaders:
    async def test_security_headers_are_present(self, client):
        response = await client.get("/api/status")
        assert response.status_code == 200
        assert response.headers["X-Frame-Options"] == "DENY"
        assert response.headers["X-Content-Type-Options"] == "nosniff"
        assert response.headers["Referrer-Policy"] == "no-referrer"
        assert response.headers["Cache-Control"] == "no-store"
        assert "default-src 'self'" in response.headers["Content-Security-Policy"]

    async def test_hsts_absent_by_default(self, client):
        # En développement on sert du HTTP : un HSTS ici serait ignoré
        # par le navigateur et potentiellement piégeant.
        response = await client.get("/api/status")
        assert "Strict-Transport-Security" not in response.headers

    async def test_hsts_present_when_configured(self, client, monkeypatch):
        monkeypatch.setattr(settings, "hsts_max_age", 31536000)
        response = await client.get("/api/status")
        assert (
            response.headers["Strict-Transport-Security"]
            == "max-age=31536000; includeSubDomains"
        )


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


class TestGroupConversation:
    async def _make_group(self, make_client, name="Projet SDV"):
        alice = make_client()
        bob = make_client()
        carol = make_client()
        alice_info = await register_user(alice, "alice")
        bob_info = await register_user(bob, "bob")
        carol_info = await register_user(carol, "carol")
        alice_priv, pa = new_keypair()
        bob_priv, pb = new_keypair()
        carol_priv, pc = new_keypair()
        await set_public_key(alice, pa)
        await set_public_key(bob, pb)
        await set_public_key(carol, pc)
        aes_key = os.urandom(32)
        ids = [alice_info["id"], bob_info["id"], carol_info["id"]]
        publics = []
        for user_id, pub in zip(ids, (pa, pb, pc)):
            publics.append(wrap_channel_key(aes_key, pub))
        wraps = dict(zip(ids, publics))
        response = await alice.post(
            "/api/conversations",
            headers=auth_headers(await csrf(alice)),
            json={
                "member_ids": [bob_info["id"], carol_info["id"]],
                "name": name,
                "key_wraps": wraps,
            },
        )
        assert response.status_code == 201, response.text
        return {
            "alice": alice,
            "bob": bob,
            "carol": carol,
            "aes_key": aes_key,
            "infos": {
                "alice": alice_info,
                "bob": bob_info,
                "carol": carol_info,
            },
            "pubs": {"alice": pa, "bob": pb, "carol": pc},
            "privs": {"alice": alice_priv, "bob": bob_priv, "carol": carol_priv},
            "conversation_id": response.json()["id"],
        }

    async def test_create_group_flow(self, make_client):
        group = await self._make_group(make_client)
        conversation_id = group["conversation_id"]

        listing = await group["alice"].get("/api/conversations")
        convo = next(c for c in listing.json() if c["id"] == conversation_id)
        assert convo["type"] == "group"
        assert convo["name"] == "Projet SDV"
        assert convo["member_count"] == 3
        member_ids = {m["id"] for m in convo["members"]}
        assert member_ids == {group["infos"]["bob"]["id"], group["infos"]["carol"]["id"]}

        bob_listing = await group["bob"].get("/api/conversations")
        assert any(
            c["id"] == conversation_id and c["name"] == "Projet SDV"
            for c in bob_listing.json()
        )

        keys = await group["bob"].get(
            "/api/conversations/" + conversation_id + "/keys"
        )
        assert keys.status_code == 200
        unwrapped = unwrap_channel_key(keys.json()["wrapped"], group["privs"]["bob"])
        assert unwrapped == group["aes_key"]

        secret = "message de groupe chiffre"
        encrypted = encrypt_message(secret.encode(), group["aes_key"])
        sent = await group["alice"].post(
            "/api/conversations/" + conversation_id + "/messages",
            headers=auth_headers(await csrf(group["alice"])),
            json=encrypted,
        )
        assert sent.status_code == 201
        history = await group["carol"].get(
            "/api/conversations/" + conversation_id + "/messages"
        )
        assert history.status_code == 200
        stored = history.json()
        assert stored[0]["ciphertext"] != secret
        assert stored[0]["sender_username"] == group["infos"]["alice"]["username"]

        intruder = make_client()
        await register_user(intruder, "intrus")
        hidden = await intruder.get(
            "/api/conversations/" + conversation_id + "/messages"
        )
        assert hidden.status_code == 404

    async def test_group_requires_key_for_every_member(self, make_client):
        alice = make_client()
        bob = make_client()
        carol = make_client()
        alice_info = await register_user(alice, "alice")
        bob_info = await register_user(bob, "bob")
        carol_info = await register_user(carol, "carol")
        _, pa = new_keypair()
        _, pb = new_keypair()
        _, pc = new_keypair()
        await set_public_key(alice, pa)
        await set_public_key(bob, pb)
        await set_public_key(carol, pc)
        aes_key = os.urandom(32)
        response = await alice.post(
            "/api/conversations",
            headers=auth_headers(await csrf(alice)),
            json={
                "member_ids": [bob_info["id"], carol_info["id"]],
                "name": "Groupe",
                "key_wraps": {
                    alice_info["id"]: wrap_channel_key(aes_key, pa),
                    bob_info["id"]: wrap_channel_key(aes_key, pb),
                },
            },
        )
        assert response.status_code == 422

    async def test_group_rejects_self_and_duplicates(self, make_client):
        alice = make_client()
        bob = make_client()
        alice_info = await register_user(alice, "alice")
        bob_info = await register_user(bob, "bob")
        _, pa = new_keypair()
        _, pb = new_keypair()
        await set_public_key(alice, pa)
        await set_public_key(bob, pb)
        aes_key = os.urandom(32)
        wraps = {
            alice_info["id"]: wrap_channel_key(aes_key, pa),
            bob_info["id"]: wrap_channel_key(aes_key, pb),
        }
        self_dup = await alice.post(
            "/api/conversations",
            headers=auth_headers(await csrf(alice)),
            json={
                "member_ids": [alice_info["id"], bob_info["id"]],
                "key_wraps": wraps,
            },
        )
        assert self_dup.status_code == 422
        dup = await alice.post(
            "/api/conversations",
            headers=auth_headers(await csrf(alice)),
            json={
                "member_ids": [bob_info["id"], bob_info["id"]],
                "key_wraps": wraps,
            },
        )
        assert dup.status_code == 422

    async def test_rename_group(self, make_client):
        group = await self._make_group(make_client, name="Avant")
        conversation_id = group["conversation_id"]

        renamed = await group["alice"].patch(
            "/api/conversations/" + conversation_id,
            headers=auth_headers(await csrf(group["alice"])),
            json={"name": "  Après renommage  "},
        )
        assert renamed.status_code == 200, renamed.text
        assert renamed.json()["name"] == "Après renommage"

        bob_listing = await group["bob"].get("/api/conversations")
        convo = next(c for c in bob_listing.json() if c["id"] == conversation_id)
        assert convo["name"] == "Après renommage"

    async def test_direct_cannot_be_renamed(self, make_client):
        alice = make_client()
        bob = make_client()
        alice_info = await register_user(alice, "alice")
        bob_info = await register_user(bob, "bob")
        _, pa = new_keypair()
        _, pb = new_keypair()
        await set_public_key(alice, pa)
        await set_public_key(bob, pb)
        aes_key = os.urandom(32)
        direct = await alice.post(
            "/api/conversations",
            headers=auth_headers(await csrf(alice)),
            json={
                "user_id": bob_info["id"],
                "key_wraps": {
                    alice_info["id"]: wrap_channel_key(aes_key, pa),
                    bob_info["id"]: wrap_channel_key(aes_key, pb),
                },
            },
        )
        assert direct.status_code == 201
        renamed = await alice.patch(
            "/api/conversations/" + direct.json()["id"],
            headers=auth_headers(await csrf(alice)),
            json={"name": "Groupe"},
        )
        assert renamed.status_code == 422

    async def test_remove_member_revokes_access(self, make_client):
        group = await self._make_group(make_client)
        conversation_id = group["conversation_id"]
        carol_id = group["infos"]["carol"]["id"]

        removed = await group["alice"].post(
            "/api/conversations/" + conversation_id + "/members/" + carol_id + "/remove",
            headers=auth_headers(await csrf(group["alice"])),
        )
        assert removed.status_code == 200
        assert removed.json()["deleted"] is False
        assert removed.json()["member_count"] == 2

        carol_listing = await group["carol"].get("/api/conversations")
        assert not any(c["id"] == conversation_id for c in carol_listing.json())

        hidden = await group["carol"].get(
            "/api/conversations/" + conversation_id + "/messages"
        )
        assert hidden.status_code == 404

        keys = await group["carol"].get(
            "/api/conversations/" + conversation_id + "/keys"
        )
        assert keys.status_code == 404

    async def test_leave_group(self, make_client):
        group = await self._make_group(make_client)
        conversation_id = group["conversation_id"]

        left = await group["bob"].post(
            "/api/conversations/" + conversation_id + "/leave",
            headers=auth_headers(await csrf(group["bob"])),
        )
        assert left.status_code == 200
        assert left.json()["deleted"] is False
        assert left.json()["member_count"] == 2

        bob_listing = await group["bob"].get("/api/conversations")
        assert not any(c["id"] == conversation_id for c in bob_listing.json())

        alice_listing = await group["alice"].get("/api/conversations")
        convo = next(c for c in alice_listing.json() if c["id"] == conversation_id)
        assert convo["member_count"] == 2

    async def test_leave_deletes_when_less_than_two_remain(self, make_client):
        group = await self._make_group(make_client)
        conversation_id = group["conversation_id"]
        carol_id = group["infos"]["carol"]["id"]

        await group["alice"].post(
            "/api/conversations/"
            + conversation_id
            + "/members/"
            + carol_id
            + "/remove",
            headers=auth_headers(await csrf(group["alice"])),
        )
        left = await group["bob"].post(
            "/api/conversations/" + conversation_id + "/leave",
            headers=auth_headers(await csrf(group["bob"])),
        )
        assert left.status_code == 200
        assert left.json()["deleted"] is True

        alice_listing = await group["alice"].get("/api/conversations")
        assert not any(c["id"] == conversation_id for c in alice_listing.json())