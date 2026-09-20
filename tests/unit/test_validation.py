"""Tests unitaires de la validation Pydantic : usernames, mots de passe,
clés publiques SPKI RSA-2048+, base64 strict (nonce/ciphertext/wrapped_key)
et rejet des champs superflus (``extra="forbid"``).
"""

from __future__ import annotations

import base64

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import dh, rsa
from pydantic import ValidationError

from app.schemas import KeyWrapRequest, LoginRequest, MessageCreate, RegisterRequest, RoomCreate
from app.schemas.auth import valid_public_key
from app.schemas.validation import valid_base64
from tests.helpers.crypto_client import (
    default_public_key,
    generate_room_key,
    generate_user_keypair,
    wrap_key,
)

_VALID_PUBLIC_KEY = default_public_key()
_VALID_B64 = base64.b64encode(b"0123456789abcdef").decode("ascii")


def _rsa_public_key_b64(key_size: int) -> str:
    """Clé publique RSA d'une taille donnée, encodée SPKI base64."""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    der = private_key.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return base64.b64encode(der).decode("ascii")


def _dh_public_key_b64() -> str:
    """Clé publique non-RSA (diffie-hellman) : SPKI base64, ≥ 270 octets."""
    parameters = dh.generate_parameters(generator=2, key_size=2048)
    private_key = parameters.generate_private_key()
    der = private_key.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return base64.b64encode(der).decode("ascii")


# ---- usernames --------------------------------------------------------------


@pytest.mark.parametrize("username", ["ab", "a" * 33, ""])
def test_username_length_invalid(username: str) -> None:
    with pytest.raises(ValidationError):
        RegisterRequest(username=username, password="password123", public_key=_VALID_PUBLIC_KEY)


@pytest.mark.parametrize(
    "username",
    ["al*ce", "al!ce", "al ce", "al\nce", "al;ce", "al{ce}", "al[0]", "$alice", "al@ce", "al/ce"],
)
def test_username_forbidden_characters_rejected(username: str) -> None:
    with pytest.raises(ValidationError):
        RegisterRequest(username=username, password="password123", public_key=_VALID_PUBLIC_KEY)


@pytest.mark.parametrize("username", ["abc", "a" * 32, "Ali_ce.X-1", "0123456789"])
def test_username_valid_pattern_accepted(username: str) -> None:
    request = RegisterRequest(
        username=username, password="password123", public_key=_VALID_PUBLIC_KEY
    )
    assert request.username == username


# ---- mots de passe ----------------------------------------------------------


def test_register_password_too_short() -> None:
    with pytest.raises(ValidationError):
        RegisterRequest(username="alice", password="short7", public_key=_VALID_PUBLIC_KEY)


def test_register_password_too_long() -> None:
    with pytest.raises(ValidationError):
        RegisterRequest(username="alice", password="p" * 129, public_key=_VALID_PUBLIC_KEY)


def test_register_password_boundaries_accepted() -> None:
    assert RegisterRequest(username="alice", password="12345678", public_key=_VALID_PUBLIC_KEY)
    assert RegisterRequest(username="alice", password="p" * 128, public_key=_VALID_PUBLIC_KEY)


def test_login_empty_password_rejected() -> None:
    with pytest.raises(ValidationError):
        LoginRequest(username="alice", password="")


# ---- public_key SPKI RSA-2048 ------------------------------------------------


_NOT_B64 = base64.b64encode(b"\0" * 256).decode()


@pytest.mark.parametrize("bad", ["", "not-base64!!", "§§§", "aaaa", _NOT_B64])
def test_public_key_not_valid_base64_rejected(bad: str) -> None:
    with pytest.raises(ValidationError):
        RegisterRequest(username="alice", password="password123", public_key=bad)


def test_public_key_not_a_der_key_rejected() -> None:
    long_garbage = base64.b64encode(b"x" * 300).decode()
    with pytest.raises(ValidationError):
        RegisterRequest(username="alice", password="password123", public_key=long_garbage)


def test_public_key_not_rsa_rejected() -> None:
    """Une clé publique DH (non-RSA) de taille suffisante est refusée."""
    with pytest.raises(ValidationError):
        RegisterRequest(username="alice", password="password123", public_key=_dh_public_key_b64())


def test_public_key_rsa_too_small_rejected() -> None:
    with pytest.raises(ValidationError):
        RegisterRequest(
            username="alice", password="password123", public_key=_rsa_public_key_b64(1024)
        )


def test_public_key_too_long_rejected() -> None:
    too_long = _VALID_PUBLIC_KEY + "A" * (1000 - len(_VALID_PUBLIC_KEY) + 1)
    with pytest.raises(ValidationError):
        RegisterRequest(username="alice", password="password123", public_key=too_long)


def test_public_key_valid_spki_accepted() -> None:
    _, public_key = generate_user_keypair()
    request = RegisterRequest(username="alice", password="password123", public_key=public_key)
    assert request.public_key == public_key
    assert valid_public_key(public_key) == public_key


# ---- base64 strict (messages + clés enveloppées) ------------------------------


_URLSAFE_DERIVED = base64.urlsafe_b64encode(b"\xfb\xff\xff").decode()


@pytest.mark.parametrize("bad", ["", "not-base64!!", "§§§", "====", _URLSAFE_DERIVED])
def test_message_nonce_or_ciphertext_invalid_base64_rejected(bad: str) -> None:
    with pytest.raises(ValidationError):
        MessageCreate(nonce=bad, ciphertext=_VALID_B64)


def test_message_valid_base64_accepted() -> None:
    nonce, ciphertext = base64.b64encode(b"\x01" * 12).decode(), _VALID_B64
    message = MessageCreate(nonce=nonce, ciphertext=ciphertext)
    assert message.ciphertext == ciphertext


def test_valid_base64_rejects_urlsafe_or_unpadded() -> None:
    assert valid_base64(_VALID_B64) == _VALID_B64
    with pytest.raises(ValueError):
        valid_base64("YWJjZA")  # padding manquant
    with pytest.raises(ValueError):
        valid_base64("YWJjZA-=")  # alphabet urlsafe interdit


def test_wrapped_key_must_be_base64() -> None:
    with pytest.raises(ValidationError):
        KeyWrapRequest(target_user_id="u1", wrapped_key="!!!")
    room_key = generate_room_key()
    _, public_key = generate_user_keypair()

    wrapped = wrap_key(public_key, room_key)
    assert KeyWrapRequest(target_user_id="u1", wrapped_key=wrapped).wrapped_key == wrapped


# ---- salons et corps superflus ------------------------------------------------


def test_room_name_empty_or_too_long_rejected() -> None:
    with pytest.raises(ValidationError):
        RoomCreate(name="")
    with pytest.raises(ValidationError):
        RoomCreate(name="x" * 65)


def test_extra_body_field_rejected() -> None:
    """``extra="forbid"`` : tout champ inconnu est rejeté (422)."""
    payload = {"username": "alice", "password": "password123", "public_key": _VALID_PUBLIC_KEY}
    payload["is_admin"] = True
    with pytest.raises(ValidationError):
        RegisterRequest.model_validate(payload)

    message_payload = {"nonce": _VALID_B64, "ciphertext": _VALID_B64, "room_id": "abc"}
    with pytest.raises(ValidationError):
        MessageCreate.model_validate(message_payload)
