"""Protocole de chiffrement de bout en bout (implémentation de référence côté client)."""

import pytest
from cryptography.exceptions import InvalidTag

from tests.helpers import e2e


def test_message_roundtrip_with_unicode():
    key = e2e.generate_room_key()
    message = e2e.encrypt_message(key, "Salut 👋 — ça va ?", "room-1", "user-1")
    message.update(room_id="room-1", sender_id="user-1")
    assert e2e.decrypt_message(key, message) == "Salut 👋 — ça va ?"


def test_ciphertext_does_not_contain_plaintext():
    key = e2e.generate_room_key()
    message = e2e.encrypt_message(key, "message très secret", "r", "u")
    assert "secret" not in message["ciphertext"]
    assert b"secret" not in e2e.unb64(message["ciphertext"])


def test_each_message_gets_a_fresh_iv():
    key = e2e.generate_room_key()
    ivs = {e2e.encrypt_message(key, "x", "r", "u")["iv"] for _ in range(200)}
    assert len(ivs) == 200


def test_tampered_ciphertext_is_detected():
    key = e2e.generate_room_key()
    message = e2e.encrypt_message(key, "bonjour", "r", "u")
    raw = bytearray(e2e.unb64(message["ciphertext"]))
    raw[0] ^= 1
    message.update(ciphertext=e2e.b64(bytes(raw)), room_id="r", sender_id="u")
    with pytest.raises(InvalidTag):
        e2e.decrypt_message(key, message)


def test_message_cannot_be_replayed_in_another_room_or_as_another_sender():
    key = e2e.generate_room_key()
    message = e2e.encrypt_message(key, "bonjour", "salon-A", "alice")
    with pytest.raises(InvalidTag):
        e2e.decrypt_message(key, {**message, "room_id": "salon-B", "sender_id": "alice"})
    with pytest.raises(InvalidTag):
        e2e.decrypt_message(key, {**message, "room_id": "salon-A", "sender_id": "mallory"})


def test_wrong_room_key_cannot_decrypt():
    message = e2e.encrypt_message(e2e.generate_room_key(), "bonjour", "r", "u")
    with pytest.raises(InvalidTag):
        e2e.decrypt_message(e2e.generate_room_key(), {**message, "room_id": "r", "sender_id": "u"})


def test_room_key_wrapping_roundtrip_and_only_recipient_can_unwrap():
    alice, bob = e2e.Identity.create("alice"), e2e.Identity.create("bob")
    room_key = e2e.generate_room_key()
    wrapped = e2e.wrap_room_key(room_key, bob.public_key)
    assert e2e.unwrap_room_key(wrapped, bob.private_key) == room_key
    with pytest.raises(InvalidTag):
        e2e.unwrap_room_key(wrapped, alice.private_key)


def test_wrapped_key_does_not_reveal_the_room_key():
    bob = e2e.Identity.create("bob")
    room_key = e2e.generate_room_key()
    wrapped = e2e.wrap_room_key(room_key, bob.public_key)
    assert room_key not in b"".join(e2e.unb64(value) for value in wrapped.values())


def test_wrapping_twice_uses_fresh_ephemeral_keys():
    bob = e2e.Identity.create("bob")
    room_key = e2e.generate_room_key()
    first, second = e2e.wrap_room_key(room_key, bob.public_key), e2e.wrap_room_key(room_key, bob.public_key)
    assert first["ephemeral_public_key"] != second["ephemeral_public_key"]
    assert first["iv"] != second["iv"]


def test_private_key_backup_needs_the_password_derived_key():
    identity = e2e.Identity.create("alice", "mot de passe correct")
    blob = e2e.encrypt_private_key(identity.private_key, identity.wrap_key)
    restored = e2e.decrypt_private_key(blob, identity.wrap_key)
    assert e2e.public_key_b64(restored.public_key()) == identity.public_key

    wrong_key, _ = e2e.derive_keys("mauvais mot de passe", "alice")
    with pytest.raises(InvalidTag):
        e2e.decrypt_private_key(blob, wrong_key)


def test_auth_secret_and_wrap_key_are_independent():
    """Le serveur reçoit le secret d'authentification : il ne doit pas révéler la clé d'enveloppe."""
    wrap_key, auth_secret = e2e.derive_keys("mot de passe", "alice")
    assert e2e.unb64(auth_secret) != wrap_key
    assert e2e.derive_keys("mot de passe", "alice") == (wrap_key, auth_secret)  # déterministe
    assert e2e.derive_keys("mot de passe", "bob")[1] != auth_secret  # sel propre à l'utilisateur
