from uuid import uuid4

from conftest import TEST_ORIGIN, create_room, encrypted_message, register_user
from fastapi.testclient import TestClient


def test_room_channel_and_encrypted_message_flow(client, redis_client):
    registered = register_user(client, "alice")
    room_data = create_room(client, name="Équipe")
    room = room_data["room"]
    channel = room_data["channels"][0]
    assert room["name"] == "Équipe"
    assert channel["name"] == "général"
    assert client.get("/api/rooms").json()["rooms"][0]["id"] == room["id"]

    payload = encrypted_message()
    response = client.post(
        f"/api/channels/{channel['id']}/messages",
        headers={
            "X-CSRF-Token": room_data["csrf_token"],
            "Origin": TEST_ORIGIN,
        },
        json=payload,
    )
    assert response.status_code == 201, response.text
    stored_message = response.json()
    assert stored_message["sender_id"] == registered["user"]["id"]
    assert stored_message["ciphertext"] == payload["ciphertext"]
    assert "plaintext" not in stored_message

    redis_record = client.portal.call(
        redis_client.hgetall,
        f"talk:message:{payload['client_id']}",
    )
    assert redis_record["ciphertext"] == payload["ciphertext"]
    assert set(redis_record) == {
        "client_id",
        "sender_id",
        "room_id",
        "channel_id",
        "algorithm",
        "key_version",
        "ciphertext",
        "nonce",
        "created_at",
        "sequence",
    }

    history = client.get(f"/api/channels/{channel['id']}/messages").json()
    assert [item["client_id"] for item in history["messages"]] == [payload["client_id"]]
    assert history["messages"][0]["sender"]["username"] == "alice"

    duplicate = client.post(
        f"/api/channels/{channel['id']}/messages",
        headers={
            "X-CSRF-Token": room_data["csrf_token"],
            "Origin": TEST_ORIGIN,
        },
        json=payload,
    )
    assert duplicate.status_code == 201
    assert duplicate.json()["client_id"] == payload["client_id"]


def test_message_rejects_plaintext_field(client):
    register_user(client, "alice")
    room_data = create_room(client)
    channel = room_data["channels"][0]
    payload = encrypted_message()
    payload["plaintext"] = "TOP_SECRET_MESSAGE"
    response = client.post(
        f"/api/channels/{channel['id']}/messages",
        headers={
            "X-CSRF-Token": room_data["csrf_token"],
            "Origin": TEST_ORIGIN,
        },
        json=payload,
    )
    assert response.status_code == 422
    assert "TOP_SECRET_MESSAGE" not in response.text


def test_room_and_channel_authorization(app, client):
    alice = register_user(client, "alice")
    room_data = create_room(client)
    room_id = room_data["room"]["id"]
    channel_id = room_data["channels"][0]["id"]

    with TestClient(app, base_url=TEST_ORIGIN) as bob_client:
        bob = register_user(bob_client, "bob")
        assert bob_client.get("/api/rooms").json()["rooms"] == []
        assert bob_client.get(f"/api/rooms/{room_id}").status_code == 404
        assert bob_client.get(f"/api/rooms/{room_id}/keys").status_code == 404
        assert bob_client.get(f"/api/channels/{channel_id}/messages").status_code == 404
        denied_message = bob_client.post(
            f"/api/channels/{channel_id}/messages",
            headers={
                "X-CSRF-Token": bob["csrf_token"],
                "Origin": TEST_ORIGIN,
            },
            json=encrypted_message(),
        )
        assert denied_message.status_code == 404
    assert alice["user"]["username"] == "alice"


def test_only_owner_can_rotate_keys(app, client):
    register_user(client, "alice")
    room_data = create_room(client)
    room = room_data["room"]
    with TestClient(app, base_url=TEST_ORIGIN) as bob_client:
        bob = register_user(bob_client, "bob")
        bob_keys = bob_client.get("/api/users/bob/keys").json()
        alice = client.get("/api/users/alice/keys").json()
        envelopes = []
        for result in (alice, bob_keys):
            envelope = {
                "recipient_id": result["user"]["id"],
                "key_id": result["identity_keys"][0]["key_id"],
                "algorithm": "RSA-OAEP-256",
                "wrapped_key": "A" * 43,
                "key_version": 1,
            }
            envelopes.append(envelope)
        add_member = client.post(
            f"/api/rooms/{room['id']}/members",
            headers={
                "X-CSRF-Token": client.get("/api/auth/csrf").json()["csrf_token"],
                "Origin": TEST_ORIGIN,
            },
            json={"username": "bob", "key_envelopes": [envelopes[1]]},
        )
        assert add_member.status_code == 201
        denied = bob_client.post(
            f"/api/rooms/{room['id']}/keys/rotate",
            headers={
                "X-CSRF-Token": bob["csrf_token"],
                "Origin": TEST_ORIGIN,
            },
            json={"key_envelopes": envelopes},
        )
        assert denied.status_code == 403


def test_invalid_nonce_and_stale_key_are_rejected(client):
    register_user(client, "alice")
    room_data = create_room(client)
    channel_id = room_data["channels"][0]["id"]
    payload = encrypted_message()
    payload["nonce"] = "not-base64!"
    invalid_nonce = client.post(
        f"/api/channels/{channel_id}/messages",
        headers={
            "X-CSRF-Token": room_data["csrf_token"],
            "Origin": TEST_ORIGIN,
        },
        json=payload,
    )
    assert invalid_nonce.status_code == 422

    stale = encrypted_message(key_version=2)
    stale_response = client.post(
        f"/api/channels/{channel_id}/messages",
        headers={
            "X-CSRF-Token": room_data["csrf_token"],
            "Origin": TEST_ORIGIN,
        },
        json=stale,
    )
    assert stale_response.status_code == 409


def test_random_unknown_identifiers_do_not_leak_data(client):
    register_user(client, "alice")
    assert client.get(f"/api/rooms/{uuid4()}").status_code == 404
    assert client.get(f"/api/channels/{uuid4()}/messages").status_code == 404
