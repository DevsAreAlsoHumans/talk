"""Tests du flux auth + CSRF complet, sur une BDD en mémoire.

Sans BDD réelle, on surcharge `get_db` (voir conftest.py) : les tests restent
déterministes et rapides.
"""

from fastapi.testclient import TestClient

from app.security import hash_password, verify_password


def _csrf(client: TestClient) -> str:
    r = client.get("/api/auth/csrf")
    assert r.status_code == 200
    return r.json()["csrf_token"]


def test_argon2_roundtrip() -> None:
    h = hash_password("P4ssw0rdX!")
    assert verify_password("P4ssw0rdX!", h)
    assert not verify_password("wrong-pass", h)


def test_register_and_me(client: TestClient) -> None:
    csrf = _csrf(client)
    r = client.post(
        "/api/auth/register",
        json={"username": "alice", "password": "P4ssw0rdX!"},
        headers={"X-CSRF-Token": csrf},
    )
    assert r.status_code == 201
    assert r.json()["username"] == "alice"

    # Session HttpOnly posée -> /me répond sans autre facteur
    me = client.get("/api/auth/me")
    assert me.status_code == 200
    assert me.json()["username"] == "alice"


def test_duplicate_register_rejected(client: TestClient) -> None:
    csrf = _csrf(client)
    payload = {"username": "bob", "password": "P4ssw0rdX!"}
    r = client.post("/api/auth/register", json=payload, headers={"X-CSRF-Token": csrf})
    assert r.status_code == 201
    # Rotation CSRF après login : le client relit le cookie, puis jeux de tests
    csrf = _csrf(client)
    # même pseudo -> 409, et la réponse ne révèle rien de plus
    r = client.post("/api/auth/register", json=payload, headers={"X-CSRF-Token": csrf})
    assert r.status_code == 409


def test_login_then_create_room(client: TestClient) -> None:
    csrf = _csrf(client)
    r = client.post(
        "/api/auth/register",
        json={"username": "carol", "password": "P4ssw0rdX!"},
        headers={"X-CSRF-Token": csrf},
    )
    assert r.status_code == 201

    # logout invalide la session
    r = client.post("/api/auth/logout", headers={"X-CSRF-Token": _csrf(client)})
    assert r.status_code == 204
    assert client.get("/api/auth/me").status_code == 401

    # re-login avec le jeton CSRF courant
    csrf = _csrf(client)
    r = client.post("/api/auth/login", json={"username": "carol", "password": "P4ssw0rdX!"},
                    headers={"X-CSRF-Token": csrf})
    assert r.status_code == 200

    csrf = _csrf(client)
    room = client.post("/api/rooms", json={"name": "général"}, headers={"X-CSRF-Token": csrf})
    assert room.status_code == 201
    assert room.json()["name"] == "général"


def test_csrf_protection_blocks_forged(client: TestClient) -> None:
    csrf = _csrf(client)
    client.post("/api/auth/register", json={"username": "dave", "password": "P4ssw0rdX!"},
                headers={"X-CSRF-Token": csrf})
    # Requête de mutation SANS header CSRF -> rejetée par la protection
    r = client.post("/api/rooms", json={"name": "forgé"})
    assert r.status_code == 403
