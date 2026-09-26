"""Hachage des mots de passe : jamais en clair, Argon2id, sel par utilisateur."""

from __future__ import annotations

from fastapi.testclient import TestClient

from app.config import SESSION_COOKIE_NAME, get_settings
from app.security import (
    burn_password_verification,
    generate_token,
    hash_password,
    hash_token,
    tokens_equal,
    verify_password,
)
from tests.conftest import VALID_PASSWORD, csrf_headers, sync_database, unique_username


def test_stored_document_never_contains_the_plaintext_password(client: TestClient) -> None:
    username = unique_username()
    client.post(
        "/auth/register",
        json={"username": username, "password": VALID_PASSWORD},
        headers=csrf_headers(client),
    )

    mongo = sync_database()
    try:
        stored = mongo["talk_test"].users.find_one({"username": username})
    finally:
        mongo.close()

    assert stored is not None
    serialized = str(stored)
    assert VALID_PASSWORD not in serialized
    assert stored["password_hash"] != VALID_PASSWORD
    assert stored["password_hash"].startswith("$argon2id$")


def test_session_documents_store_only_the_token_footprint(client: TestClient) -> None:
    client.get("/auth/csrf")
    raw_token = client.cookies.get(SESSION_COOKIE_NAME) or ""

    mongo = sync_database()
    try:
        sessions = list(mongo[get_settings().mongo_db_name].sessions.find({}))
    finally:
        mongo.close()

    assert sessions
    assert raw_token not in str(sessions)
    assert all(session["token_hash"] == hash_token(raw_token) for session in sessions)


def test_hash_is_argon2id_and_never_equals_the_password() -> None:
    hashed = hash_password(VALID_PASSWORD)

    assert hashed != VALID_PASSWORD
    assert hashed.startswith("$argon2id$")
    assert VALID_PASSWORD not in hashed


def test_same_password_produces_a_different_hash_each_time() -> None:
    """Deux hachés du même mot de passe diffèrent : le sel est aléatoire."""
    assert hash_password(VALID_PASSWORD) != hash_password(VALID_PASSWORD)


def test_verify_accepts_the_right_password() -> None:
    assert verify_password(VALID_PASSWORD, hash_password(VALID_PASSWORD)) is True


def test_verify_rejects_a_wrong_password_without_raising() -> None:
    hashed = hash_password(VALID_PASSWORD)

    assert verify_password("mauvais-mot-de-passe", hashed) is False


def test_verify_rejects_a_malformed_hash_without_raising() -> None:
    """Une donnée corrompue ne doit pas provoquer une erreur 500."""
    assert verify_password(VALID_PASSWORD, "pas-un-haché") is False
    assert verify_password(VALID_PASSWORD, "") is False


def test_burn_password_verification_never_raises() -> None:
    burn_password_verification("un-mot-de-passe-au-hasard")


def test_token_helpers() -> None:
    token = generate_token()

    assert len(token) >= 43
    assert hash_token(token) == hash_token(token)
    assert hash_token(token) != token
    assert tokens_equal(token, token) is True
    assert tokens_equal(token, generate_token()) is False


def test_tokens_equal_tolerates_arbitrary_input() -> None:
    """Un en-tête non ASCII ne doit pas provoquer de TypeError."""
    assert tokens_equal("café", "autre") is False
    assert tokens_equal("", "x") is False
