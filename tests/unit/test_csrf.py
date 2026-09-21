"""Jetons CSRF (signature, liaison à la session) et contrôle d'origine."""

import pytest

from app.security.csrf import generate_csrf_token, is_valid_csrf_token, origin_is_allowed

SECRET = "cle-de-test-uniquement-0123456789abcdef"
ALLOWED = ["https://talk.example.com", "http://localhost:8000"]


def test_token_is_valid_for_the_session_it_was_issued_for():
    token = generate_csrf_token(SECRET, "session-1")
    assert is_valid_csrf_token(SECRET, "session-1", token)


def test_anonymous_token_is_valid_without_session():
    token = generate_csrf_token(SECRET, None)
    assert is_valid_csrf_token(SECRET, None, token)


def test_token_is_bound_to_its_session():
    token = generate_csrf_token(SECRET, "session-1")
    assert not is_valid_csrf_token(SECRET, "session-2", token)
    assert not is_valid_csrf_token(SECRET, None, token)


def test_token_signed_with_another_key_is_rejected():
    token = generate_csrf_token("une-autre-cle-secrete-0123456789abcdef", "session-1")
    assert not is_valid_csrf_token(SECRET, "session-1", token)


def test_tokens_are_unique():
    assert generate_csrf_token(SECRET, "s") != generate_csrf_token(SECRET, "s")


@pytest.mark.parametrize("token", [None, "", "sans-point", ".signature", "nonce.", "a.b.c"])
def test_malformed_tokens_are_rejected(token):
    assert not is_valid_csrf_token(SECRET, "session-1", token)


def test_tampered_signature_is_rejected():
    token = generate_csrf_token(SECRET, "session-1")
    nonce, signature = token.split(".")
    tampered = f"{nonce}.{'0' * len(signature)}"
    assert not is_valid_csrf_token(SECRET, "session-1", tampered)


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("https://talk.example.com", True),
        ("http://localhost:8000", True),
        ("https://talk.example.com/page?x=1", True),  # Referer complet
        ("https://evil.example.com", False),
        ("https://talk.example.com.evil.com", False),
        ("http://talk.example.com", False),  # mauvais schéma
        ("null", False),
        ("", False),
        (None, False),
    ],
)
def test_origin_check(value, expected):
    assert origin_is_allowed(value, ALLOWED) is expected
