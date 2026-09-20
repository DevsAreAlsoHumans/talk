"""Tests unitaires de la logique métier des repositories (fakeredis).

Couvre : unicité du nom d'utilisateur, salons (création/ajout/membres/index),
messages (séquences croissantes, ``after`` exclusif) et clés enveloppées.
"""

from __future__ import annotations

from app.repositories import messages, rooms, users

_PUBLIC_KEY = "SPKI-RSA-2048-placeholder"


def _make_user(redis, username: str) -> dict:
    user = users.create_user(redis, username, f"$argon2id$hash-{username}", _PUBLIC_KEY)
    assert user is not None
    return user


# ---- utilisateurs ------------------------------------------------------------


def test_create_user_and_fetch_by_username_and_id(redis) -> None:
    user = _make_user(redis, "alice")
    assert users.get_by_username(redis, "alice")["id"] == user["id"]
    assert users.get_by_id(redis, user["id"])["username"] == "alice"


def test_username_uniqueness_enforced(redis) -> None:
    _make_user(redis, "alice")
    duplicate = users.create_user(redis, "alice", "autre-hash", _PUBLIC_KEY)
    assert duplicate is None
    # L'index d'unicité n'a pas bougé.
    assert users.get_by_username(redis, "alice")["id"]


def test_public_form_never_exposes_password(redis) -> None:
    user = _make_user(redis, "alice")
    public = users.to_public(user)
    assert set(public) == {"id", "username", "public_key", "created_at"}
    assert "password" not in public and "password_hash" not in public


def test_unknown_user_returns_none(redis) -> None:
    assert users.get_by_username(redis, "inexistant") is None
    assert users.get_by_id(redis, "inconnu") is None


# ---- salons ------------------------------------------------------------------


def test_room_creation_sets_owner_as_member(redis) -> None:
    alice = _make_user(redis, "alice")
    room = rooms.create_room(redis, "general", alice["id"])
    assert rooms.get_room(redis, room["id"]) == room
    assert rooms.is_member(redis, room["id"], alice["id"]) is True
    assert room["owner_id"] == alice["id"]


def test_room_add_remove_member_updates_indexes(redis) -> None:
    alice = _make_user(redis, "alice")
    bob = _make_user(redis, "bob")
    room = rooms.create_room(redis, "general", alice["id"])

    rooms.add_member(redis, room["id"], bob["id"])
    assert rooms.is_member(redis, room["id"], bob["id"]) is True
    assert any(r["id"] == room["id"] for r in rooms.list_for_user(redis, bob["id"]))

    rooms.remove_member(redis, room["id"], bob["id"])
    assert rooms.is_member(redis, room["id"], bob["id"]) is False
    assert all(r["id"] != room["id"] for r in rooms.list_for_user(redis, bob["id"]))


def test_room_list_members_public_and_sorted(redis) -> None:
    alice = _make_user(redis, "alice")
    bob = _make_user(redis, "bob")
    room = rooms.create_room(redis, "general", alice["id"])
    rooms.add_member(redis, room["id"], bob["id"])

    members = rooms.list_members(redis, room["id"])
    assert [m["username"] for m in members] == ["alice", "bob"]
    assert set(members[0]) == {"id", "username", "public_key"}
    assert "password_hash" not in members[0]


def test_room_list_for_user_contains_owned_rooms(redis) -> None:
    alice = _make_user(redis, "alice")
    first = rooms.create_room(redis, "un", alice["id"])
    second = rooms.create_room(redis, "deux", alice["id"])
    listed = rooms.list_for_user(redis, alice["id"])
    assert {room["id"] for room in listed} == {first["id"], second["id"]}
    # Trié par date de création.
    assert listed[0]["id"] == first["id"]


# ---- messages ----------------------------------------------------------------


def test_message_sequence_increases_per_room(redis) -> None:
    first = messages.create_message(redis, "room1", "u1", "bm9uY2U=", "Y2lwaGVy")
    second = messages.create_message(redis, "room1", "u1", "bm9uY2U=", "Y2lwaGVy")
    assert first["seq"] == 1
    assert second["seq"] == 2
    assert first["id"] != second["id"]


def test_messages_after_is_exclusive_and_ordered(redis) -> None:
    created = [
        messages.create_message(redis, "room1", "u1", "bm9uY2U=", f"Y2lwaGVy{i}") for i in range(4)
    ]
    assert messages.list_messages_after(redis, "room1", 0) == created
    after_one = messages.list_messages_after(redis, "room1", 1)
    assert [m["seq"] for m in after_one] == [2, 3, 4]
    after_four = messages.list_messages_after(redis, "room1", 4)
    assert after_four == []


def test_message_sequences_are_room_scoped(redis) -> None:
    messages.create_message(redis, "room_a", "u1", "bm9uY2U=", "Y2lwaGVy")
    first_b = messages.create_message(redis, "room_b", "u1", "bm9uY2U=", "Y2lwaGVy")
    assert first_b["seq"] == 1


def test_stored_message_is_encrypted_only(redis) -> None:
    plaintext = "PLAINTEXT-SECRET"
    message = messages.create_message(redis, "room1", "u1", "bm9uY2U=", "c2lwaGVyLXNlY3JldA==")
    stored = redis.hgetall(f"message:{message['id']}")
    assert stored["ciphertext"] == "c2lwaGVyLXNlY3JldA=="
    assert stored["nonce"] == "bm9uY2U="
    joined = " ".join(stored.values())
    assert plaintext not in joined


# ---- clés enveloppées ---------------------------------------------------------


def test_wrapped_keys_store_and_list(redis) -> None:
    rooms.store_wrapped_key(redis, "room1", "user_b", "ZW52ZWxvcHBlLXYx")
    rooms.store_wrapped_key(redis, "room1", "user_c", "ZW52ZWxvcHBlLXYy")
    keys = rooms.list_wrapped_keys(redis, "room1")
    assert keys == {"user_b": "ZW52ZWxvcHBlLXYx", "user_c": "ZW52ZWxvcHBlLXYy"}
    assert rooms.list_wrapped_keys(redis, "autre-salon") == {}
