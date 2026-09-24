import os

import pytest
from cryptography.exceptions import InvalidTag

from tests.crypto_helpers import (
    decrypt_message,
    encrypt_message,
    new_keypair,
    unwrap_channel_key,
    wrap_channel_key,
)


def test_channel_key_wrap_roundtrip():
    aes_key = os.urandom(32)
    private_key, public_key = new_keypair()
    wrapped = wrap_channel_key(aes_key, public_key)
    unwrapped = unwrap_channel_key(wrapped, private_key)
    assert unwrapped == aes_key


def test_message_encrypt_decrypt_roundtrip():
    aes_key = os.urandom(32)
    secret = b"salut, ceci est un message secret"
    payload = encrypt_message(secret, aes_key)
    assert payload["ciphertext"] != secret.decode()
    assert secret.decode() not in payload["ciphertext"]
    assert decrypt_message(payload, aes_key) == secret
    assert decrypt_message(payload, aes_key).decode() == secret.decode()


def test_message_is_encrypted_in_transit():
    aes_key = os.urandom(32)
    secret = b"je suis en clair nulle part"
    payload = encrypt_message(secret, aes_key)
    assert secret.decode() not in payload["ciphertext"]


def test_tampered_message_is_detected():
    aes_key = os.urandom(32)
    payload = encrypt_message(b"message authentique", aes_key)
    tampered = {
        "iv": payload["iv"],
        "ciphertext": ("A" * len(payload["ciphertext"])),
    }
    with pytest.raises(InvalidTag):
        decrypt_message(tampered, aes_key)


def test_wrong_key_cannot_decrypt():
    key_a = os.urandom(32)
    key_b = os.urandom(32)
    payload = encrypt_message(b"reserve a la cle A", key_a)
    with pytest.raises(InvalidTag):
        decrypt_message(payload, key_b)


def test_unique_ivs_per_message():
    aes_key = os.urandom(32)
    first = encrypt_message(b"aaaa", aes_key)
    second = encrypt_message(b"aaaa", aes_key)
    assert first["iv"] != second["iv"]