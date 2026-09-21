"""Messagerie chiffrée de bout en bout : parcours complet et garanties côté serveur."""

import json

from tests.helpers import e2e
from tests.helpers.redis_dump import dump_redis


def test_full_journey_register_login_room_send_receive_history(alice, bob):
    room_id = alice.create_room("projet")
    alice.add_member(room_id, bob)
    bob.load_room_key(room_id)

    assert alice.send(room_id, "Salut Bob !").status_code == 201
    assert bob.send(room_id, "Salut Alice 👋").status_code == 201
    assert alice.send(room_id, "On révise ce soir ?").status_code == 201

    expected = ["Salut Bob !", "Salut Alice 👋", "On révise ce soir ?"]
    assert alice.read(room_id) == expected
    assert bob.read(room_id) == expected


def test_history_is_ordered_and_paginated(alice):
    room_id = alice.create_room()
    for number in range(1, 8):
        alice.send(room_id, f"message {number}")

    page = alice.get(f"/api/rooms/{room_id}/messages", params={"limit": 3}).json()
    assert page["has_more"] is True
    assert [m["seq"] for m in page["messages"]] == [5, 6, 7]

    older = alice.get(f"/api/rooms/{room_id}/messages", params={"limit": 3, "before": 5}).json()
    assert [m["seq"] for m in older["messages"]] == [2, 3, 4]
    assert older["has_more"] is True

    oldest = alice.get(f"/api/rooms/{room_id}/messages", params={"limit": 3, "before": 2}).json()
    assert [m["seq"] for m in oldest["messages"]] == [1]
    assert oldest["has_more"] is False


def test_history_limits_are_validated(alice):
    room_id = alice.create_room()
    for params in [{"limit": 0}, {"limit": 101}, {"before": 0}, {"before": "abc"}, {"limit": "x"}]:
        assert alice.get(f"/api/rooms/{room_id}/messages", params=params).status_code == 422


def test_server_never_stores_plaintext_or_keys(alice, bob, raw_redis):
    secret_text = "le mot de passe du wifi est PATATE-42"
    room_id = alice.create_room("secrets")
    alice.add_member(room_id, bob)
    alice.send(room_id, secret_text)

    room_key = alice.room_keys[room_id]
    private_keys = [
        actor.identity.private_key.private_numbers().private_value.to_bytes(32, "big")
        for actor in (alice, bob)
    ]

    dump = dump_redis(raw_redis)

    assert "PATATE" not in dump
    assert secret_text not in dump
    forbidden = [room_key, *private_keys, alice.identity.wrap_key]
    for secret in forbidden:
        assert e2e.b64(secret) not in dump
        assert secret.hex() not in dump
    assert alice.identity.password not in dump
    assert alice.identity.auth_secret not in dump  # seul son hash Argon2 est stocké


def test_stored_message_is_only_ciphertext(alice, raw_redis):
    room_id = alice.create_room()
    alice.send(room_id, "texte en clair")
    (stored,) = raw_redis.zrange(f"room:{room_id}:messages", 0, -1)
    message = json.loads(stored)
    assert set(message) == {
        "id",
        "seq",
        "room_id",
        "sender_id",
        "sender_username",
        "kind",
        "mime",
        "iv",
        "ciphertext",
        "created_at",
    }
    assert "texte en clair" not in stored


def test_a_member_who_joined_later_reads_the_whole_history(alice, bob):
    room_id = alice.create_room()
    alice.send(room_id, "avant l'arrivée de Bob")
    alice.add_member(room_id, bob)
    bob.load_room_key(room_id)
    assert bob.read(room_id) == ["avant l'arrivée de Bob"]


def test_a_non_member_holding_the_ciphertext_cannot_read_it(alice, bob):
    """Même avec le texte chiffré, sans la clé enveloppée pour lui, Bob ne peut rien déchiffrer."""
    import pytest
    from cryptography.exceptions import InvalidTag

    room_id = alice.create_room()
    alice.send(room_id, "confidentiel")
    stored = alice.get(f"/api/rooms/{room_id}/messages").json()["messages"][0]
    with pytest.raises(InvalidTag):
        e2e.decrypt_message(e2e.generate_room_key(), stored)  # une clé au hasard ne marche pas
    assert bob.get(f"/api/rooms/{room_id}/messages").status_code == 404


def test_iv_reuse_is_refused(alice):
    room_id = alice.create_room()
    payload = e2e.encrypt_message(alice.room_keys[room_id], "premier", room_id, alice.user_id)
    assert alice.post(f"/api/rooms/{room_id}/messages", payload).status_code == 201

    replay = {
        **payload,
        "ciphertext": e2e.encrypt_message(alice.room_keys[room_id], "autre", room_id, alice.user_id)[
            "ciphertext"
        ],
    }
    response = alice.post(f"/api/rooms/{room_id}/messages", replay)
    assert response.status_code == 409
    assert alice.read(room_id) == ["premier"]


def test_message_rate_limit(settings, redis_backend):
    from starlette.testclient import TestClient

    from app.main import create_app
    from tests.helpers.actor import Actor

    limited = settings.model_copy(update={"message_limit": 3})
    with TestClient(create_app(limited, redis_factory=redis_backend.async_factory)) as client:
        actor = Actor(client, e2e.Identity.create("spammeur"))
        actor.register()
        actor.login()
        room_id = actor.create_room()
        statuses = [actor.send(room_id, f"spam {i}").status_code for i in range(5)]
        assert statuses == [201, 201, 201, 429, 429]


def test_oversized_and_malformed_messages_are_refused(alice):
    room_id = alice.create_room()
    key = alice.room_keys[room_id]
    too_big = e2e.encrypt_message(key, "x" * 9000, room_id, alice.user_id)
    assert alice.post(f"/api/rooms/{room_id}/messages", too_big).status_code == 422
    assert alice.post(f"/api/rooms/{room_id}/messages", {"iv": "abc", "ciphertext": "def"}).status_code == 422
    assert alice.post(f"/api/rooms/{room_id}/messages", {}).status_code == 422
    assert alice.read(room_id) == []


def test_media_message_round_trip_for_every_member(alice, bob):
    room_id = alice.create_room()
    alice.add_member(room_id, bob)
    bob.load_room_key(room_id)
    picture = bytes(range(256)) * 64  # « image » binaire quelconque

    assert alice.send_media(room_id, picture).status_code == 201

    stored = alice.get(f"/api/rooms/{room_id}/messages").json()["messages"][0]
    assert stored["kind"] == "image"
    assert stored["mime"] == "image/png"
    assert e2e.decrypt_bytes(alice.room_keys[room_id], stored) == picture
    assert e2e.decrypt_bytes(bob.room_keys[room_id], stored) == picture


def test_voice_message_round_trip(alice, bob):
    room_id = alice.create_room()
    alice.add_member(room_id, bob)
    bob.load_room_key(room_id)
    audio = b"\x1aE\xdf\xa3\x01\x00\x00\x00" + b"opus\n" * 100

    assert alice.send_media(room_id, audio, kind="voice", mime="audio/webm").status_code == 201
    stored = alice.get(f"/api/rooms/{room_id}/messages").json()["messages"][0]
    assert stored["kind"] == "voice"
    assert stored["mime"] == "audio/webm"
    assert e2e.decrypt_bytes(bob.room_keys[room_id], stored) == audio


def test_media_message_over_two_megabytes_is_refused(alice):
    room_id = alice.create_room()
    response = alice.send_media(room_id, b"x" * (2 * 1024 * 1024 + 1))
    assert response.status_code == 422
    assert alice.read(room_id) == []


def test_mime_is_required_for_media_and_forbidden_for_text(alice):
    room_id = alice.create_room()
    key = alice.room_keys[room_id]
    media = e2e.encrypt_bytes(key, b"salut", room_id, alice.user_id)
    assert alice.post(f"/api/rooms/{room_id}/messages", {**media, "kind": "image"}).status_code == 422
    text = e2e.encrypt_message(key, "salut", room_id, alice.user_id)
    response = alice.post(f"/api/rooms/{room_id}/messages", {**text, "kind": "text", "mime": "image/png"})
    assert response.status_code == 422
    assert alice.read(room_id) == []
