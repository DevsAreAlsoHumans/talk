"""Hachage des mots de passe : Argon2id, sel unique, vérification correcte."""

from argon2 import PasswordHasher

from app.security import passwords


def test_hash_is_argon2id_and_never_contains_the_secret(monkeypatch):
    monkeypatch.setattr(passwords, "_hasher", PasswordHasher())  # paramètres de production
    hashed = passwords.hash_secret("mon-secret")
    assert hashed.startswith("$argon2id$")
    assert "mon-secret" not in hashed


def test_same_secret_gives_different_hashes_thanks_to_random_salt():
    assert passwords.hash_secret("secret") != passwords.hash_secret("secret")


def test_verify_accepts_the_right_secret_and_rejects_others():
    hashed = passwords.hash_secret("bon-secret")
    assert passwords.verify_secret(hashed, "bon-secret") is True
    assert passwords.verify_secret(hashed, "mauvais-secret") is False
    assert passwords.verify_secret(hashed, "") is False


def test_verify_rejects_unknown_user_and_corrupted_hash():
    assert passwords.verify_secret(None, "quelconque") is False
    assert passwords.verify_secret("pas-un-hash", "quelconque") is False


def test_unknown_user_check_cannot_be_passed_with_the_dummy_secret():
    assert passwords.verify_secret(None, "secret-factice-pour-egaliser-les-temps") is False
