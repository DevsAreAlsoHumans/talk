"""Tests unitaires du hachage Argon2id (mot de passe jamais stocké en clair)."""

from __future__ import annotations

from app.security.passwords import hash_password, verify_password


def test_hash_and_verify_ok() -> None:
    password_hash = hash_password("S3cret-!pass")
    assert verify_password("S3cret-!pass", password_hash) is True


def test_wrong_password_rejected() -> None:
    password_hash = hash_password("S3cret-!pass")
    assert verify_password("mauvais-mot-de-passe", password_hash) is False


def test_same_password_gives_different_hashes() -> None:
    """Le sel est aléatoire : deux hashs du même mot de passe diffèrent."""
    first = hash_password("S3cret-!pass")
    second = hash_password("S3cret-!pass")
    assert first != second
    assert verify_password("S3cret-!pass", first) is True
    assert verify_password("S3cret-!pass", second) is True


def test_hash_does_not_contain_plaintext() -> None:
    password = "Clair-que-le-serveur-ne-voit-jamais"
    password_hash = hash_password(password)
    assert password not in password_hash
    assert password_hash.startswith("$argon2id$")


def test_invalid_hash_format_rejected() -> None:
    assert verify_password("mdp", "pas-un-hash-argon2") is False
    assert verify_password("mdp", "") is False
