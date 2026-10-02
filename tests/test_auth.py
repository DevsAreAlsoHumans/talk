"""Tests des comptes : inscription, connexion, déconnexion, sessions, injections."""

import pytest

from tests.conftest import PASSWORD, login, signup


def test_signup_logs_in(client):
    assert signup(client).json() == {"username": "alice"}
    assert client.get("/api/me").json() == {"username": "alice"}


def test_username_is_unique_without_case(client):
    assert signup(client).status_code == 200
    assert signup(client, "ALICE").status_code == 409


def test_password_is_not_stored_in_plain(client, stored):
    signup(client)
    user_id = stored.get("username:alice")
    user = stored.hgetall(f"user:{user_id}")
    assert user["password_hash"].startswith("$argon2id$")
    assert PASSWORD not in str(user)


def test_login_and_wrong_password(client):
    signup(client)
    client.post("/api/logout")
    assert login(client, password="mauvais-mdp").status_code == 401
    assert login(client).status_code == 200
    assert client.get("/api/me").json() == {"username": "alice"}


def test_unknown_user_gets_same_error(client):
    signup(client)
    unknown = login(client, username="bob")
    wrong = login(client, password="mauvais-mdp")
    assert unknown.status_code == wrong.status_code == 401
    assert unknown.json() == wrong.json()


def test_logout_kills_the_session(client, stored):
    signup(client)
    token = client.cookies.get("session")
    assert client.post("/api/logout").status_code == 200
    assert not stored.exists(f"session:{token}")
    # Même en remettant l'ancien cookie, la session n'existe plus
    client.cookies.set("session", token)
    assert client.get("/api/me").status_code == 401


def test_login_gives_a_new_session(client, stored):
    signup(client)
    old_token = client.cookies.get("session")
    login(client)
    assert client.cookies.get("session") != old_token
    assert not stored.exists(f"session:{old_token}")


def test_session_expires(client, stored):
    signup(client)
    token = client.cookies.get("session")
    assert 0 < stored.ttl(f"session:{token}") <= 7 * 24 * 60 * 60


def test_me_needs_a_valid_session(client):
    assert client.get("/api/me").status_code == 401
    client.cookies.set("session", "jeton-invente")
    assert client.get("/api/me").status_code == 401


@pytest.mark.parametrize("username", ["ab", "a" * 25, "bob smith", "bob:*", "<script>", "élodie"])
def test_bad_usernames_are_rejected(client, username):
    assert signup(client, username).status_code == 422


@pytest.mark.parametrize("password", ["court", "x" * 129])
def test_bad_passwords_are_rejected(client, password):
    assert signup(client, password=password).status_code == 422


# Essais d'injection NoSQL : objets, listes ou champs en trop sont refusés
@pytest.mark.parametrize("payload", [
    {"username": {"$gt": ""}, "password": PASSWORD},
    {"username": ["alice"], "password": PASSWORD},
    {"username": "alice", "password": {"$ne": None}},
    {"username": "alice", "password": PASSWORD, "admin": True},
])
def test_injection_payloads_are_rejected(client, payload):
    assert client.post("/api/signup", json=payload).status_code == 422
    assert client.post("/api/login", json=payload).status_code == 422
