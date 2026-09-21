"""Validation stricte des entrées : types, formats, longueurs, champs inattendus."""

import pytest
from pydantic import ValidationError

from app.schemas import (
    GCM_TAG_BYTES,
    MIN_AVATAR_BYTES,
    AddMemberRequest,
    AvatarRequest,
    CreateRoomRequest,
    LoginRequest,
    RegisterRequest,
    SendMessageRequest,
    UpdateProfileRequest,
)
from tests.helpers import e2e


@pytest.fixture
def identity():
    return e2e.Identity.create("alice")


def test_valid_registration(identity):
    assert RegisterRequest(**identity.registration_payload()).username == "alice"


@pytest.mark.parametrize(
    "username",
    [
        "ab",
        "A" * 3,
        "a" * 33,
        "alice bob",
        "alice:admin",
        "alice*",
        "al/ice",
        "alice\n",
        "élodie",
        "",
        "a\x00b",
    ],
)
def test_invalid_usernames_are_rejected(identity, username):
    payload = {**identity.registration_payload(), "username": username}
    with pytest.raises(ValidationError):
        RegisterRequest(**payload)


@pytest.mark.parametrize("operator_object", [{"$ne": None}, {"$gt": ""}, ["alice"], 42, None, True])
def test_non_string_values_cannot_be_smuggled_in(identity, operator_object):
    """Injection NoSQL : un objet/opérateur à la place d'une chaîne est refusé (mode strict)."""
    with pytest.raises(ValidationError):
        LoginRequest(username=operator_object, auth_secret=identity.auth_secret)
    with pytest.raises(ValidationError):
        LoginRequest(username="alice", auth_secret=operator_object)


def test_unexpected_fields_are_rejected(identity):
    with pytest.raises(ValidationError):
        RegisterRequest(**identity.registration_payload(), is_admin=True)


def test_auth_secret_must_be_32_bytes_of_base64(identity):
    for bad in ["court", "!" * 44, e2e.b64(b"x" * 31), e2e.b64(b"x" * 33)]:
        with pytest.raises(ValidationError):
            LoginRequest(username="alice", auth_secret=bad)


def test_public_key_must_be_a_real_p256_point(identity):
    payload = identity.registration_payload()
    for bad in [e2e.b64(b"\x04" + b"\x01" * 64), e2e.b64(b"\x00" * 65), e2e.b64(b"\x04" * 10)]:
        with pytest.raises(ValidationError):
            RegisterRequest(**{**payload, "public_key": bad})


@pytest.mark.parametrize("name", ["", "x" * 51, "<script>", "salon\nnouveau", "a\x00b"])
def test_invalid_room_names_are_rejected(identity, name):
    wrapped = e2e.wrap_room_key(e2e.generate_room_key(), identity.public_key)
    with pytest.raises(ValidationError):
        CreateRoomRequest(name=name, wrapped_key=wrapped)


def test_valid_room_name_with_accents_and_spaces(identity):
    wrapped = e2e.wrap_room_key(e2e.generate_room_key(), identity.public_key)
    assert CreateRoomRequest(name="Équipe révisions #1", wrapped_key=wrapped).name == "Équipe révisions #1"


def test_wrapped_key_has_a_strict_shape(identity):
    wrapped = e2e.wrap_room_key(e2e.generate_room_key(), identity.public_key)
    with pytest.raises(ValidationError):
        AddMemberRequest(username="bob", wrapped_key={**wrapped, "wrapped_key": e2e.b64(b"x" * 10)})
    with pytest.raises(ValidationError):
        AddMemberRequest(username="bob", wrapped_key={**wrapped, "extra": "x"})


def test_message_size_and_iv_limits():
    key = e2e.generate_room_key()
    good = e2e.encrypt_message(key, "x" * 8192, "r", "u")
    assert SendMessageRequest(**good)

    too_big = e2e.encrypt_message(key, "x" * 8193, "r", "u")
    with pytest.raises(ValidationError):
        SendMessageRequest(**too_big)
    with pytest.raises(ValidationError):
        SendMessageRequest(iv=e2e.b64(b"x" * 8), ciphertext=good["ciphertext"])
    with pytest.raises(ValidationError):
        SendMessageRequest(iv=good["iv"], ciphertext=e2e.b64(b"x" * 5))


def test_media_message_limits_and_mime():
    key = e2e.generate_room_key()
    room, sender = "r", "u"
    good = e2e.encrypt_bytes(key, b"x" * (2 * 1024 * 1024), room, sender)
    request = SendMessageRequest(**{**good, "kind": "image", "mime": "image/png"})
    assert request.kind == "image"
    assert request.mime == "image/png"

    too_big = e2e.encrypt_bytes(key, b"x" * (2 * 1024 * 1024 + 1), room, sender)
    with pytest.raises(ValidationError):
        SendMessageRequest(**{**too_big, "kind": "voice", "mime": "audio/webm"})
    with pytest.raises(ValidationError):
        SendMessageRequest(**{**good, "kind": "image"})  # mime requis pour un média
    with pytest.raises(ValidationError):
        SendMessageRequest(**good)  # un gros « texte » reste limité à 8 Ko
    with pytest.raises(ValidationError):
        SendMessageRequest(**{**good, "kind": "text", "mime": "image/png"})  # mime interdit sur le texte


def test_invalid_mime_types_are_rejected():
    payload = {"kind": "image", "mime": "invalid", "iv": e2e.b64(b"x" * 12), "ciphertext": e2e.b64(b"y" * 20)}
    for mime in ["image", "image/>png", "image/PNG", "<img src=x>", "image/" + "a" * 60]:
        with pytest.raises(ValidationError):
            SendMessageRequest(**{**payload, "mime": mime})


def test_profile_and_avatar_validation():
    assert UpdateProfileRequest(display_name="Alicia", bio="Maths & crypto").display_name == "Alicia"
    assert UpdateProfileRequest(display_name="ok", bio="").bio == ""  # biographie vide autorisée
    with pytest.raises(ValidationError):
        UpdateProfileRequest(display_name="<script>", bio="")
    with pytest.raises(ValidationError):
        UpdateProfileRequest(display_name="a" * 33, bio="")
    with pytest.raises(ValidationError):
        UpdateProfileRequest(display_name="ok", bio="x" * 201)

    iv = e2e.b64(b"x" * 12)
    minimum = b"y" * (MIN_AVATAR_BYTES + GCM_TAG_BYTES)
    assert AvatarRequest(iv=iv, ciphertext=e2e.b64(minimum))
    with pytest.raises(ValidationError):
        AvatarRequest(iv=iv, ciphertext=e2e.b64(b"y" * GCM_TAG_BYTES))  # chiffré trop court (1 octet clair)
    with pytest.raises(ValidationError):
        AvatarRequest(iv=iv, ciphertext=e2e.b64(b"y" * (512 * 1024 + 20)))  # avatar > 512 Ko
    with pytest.raises(ValidationError):
        AvatarRequest(iv=e2e.b64(b"x" * 8), ciphertext=e2e.b64(minimum))  # IV trop court
