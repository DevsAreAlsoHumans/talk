"""QA sécurité : injections d'entrées, mots de passe, edge-cases CSRF.

La BDD en mémoire (fixtures conftest) garde les tests déterministes et sans
Mongo — identiques sous `docker compose run --rm test`.
"""

import pytest
from conftest import register

PASSWORD = "P4ssw0rdX!"


def _csrf(client) -> str:
    r = client.get("/api/auth/csrf")
    assert r.status_code == 200
    return r.json()["csrf_token"]


@pytest.mark.parametrize(
    "username",
    [
        "$ne",
        "' OR '1'='1",
        "user name",
        "user;name",
        "a<b>c",
        "`x`",
        "user\nx",
        "usér",
        "\x00x",
    ],
)
def test_register_rejects_injected_usernames(client, username) -> None:
    r = client.post(
        "/api/auth/register",
        json={"username": username, "password": PASSWORD},
        headers={"X-CSRF-Token": _csrf(client)},
    )
    assert r.status_code == 422


def test_register_username_length_bounds(client) -> None:
    too_short = client.post(
        "/api/auth/register",
        json={"username": "ab", "password": PASSWORD},
        headers={"X-CSRF-Token": _csrf(client)},
    )
    assert too_short.status_code == 422

    too_long = client.post(
        "/api/auth/register",
        json={"username": "a" * 33, "password": PASSWORD},
        headers={"X-CSRF-Token": _csrf(client)},
    )
    assert too_long.status_code == 422

    ok = client.post(
        "/api/auth/register",
        json={"username": "a" * 32, "password": PASSWORD},
        headers={"X-CSRF-Token": _csrf(client)},
    )
    assert ok.status_code == 201


def test_register_rejects_weak_passwords(client) -> None:
    cases = [
        ("alice", "aaaaaaaaa"),        # 9 caractères
        ("alice", "a" * 129),          # trop long
        ("alice123456", "alice123456"),  # == pseudo
        ("alice", "1234567890"),       # liste noire
    ]
    for username, password in cases:
        r = client.post(
            "/api/auth/register",
            json={"username": username, "password": password},
            headers={"X-CSRF-Token": _csrf(client)},
        )
        assert r.status_code == 422, (username, password)


@pytest.mark.parametrize("name", ["li\nne", "a\tb", "\x00x", "admin", "  SYSTEM  ", "x" * 65])
def test_create_room_rejects_injected_names(client, name) -> None:
    register(client, "alice")
    r = client.post(
        "/api/rooms",
        json={"name": name},
        headers={"X-CSRF-Token": _csrf(client)},
    )
    assert r.status_code == 422


def test_create_room_strips_whitespace(client) -> None:
    register(client, "alice")
    r = client.post(
        "/api/rooms",
        json={"name": "  sala  "},
        headers={"X-CSRF-Token": _csrf(client)},
    )
    assert r.status_code == 201
    assert r.json()["name"] == "sala"


@pytest.mark.parametrize("room_id", ["$ne", "abc$def", "f" * 40, "a=b"])
def test_room_lookup_invalid_ids_404(client, room_id) -> None:
    """IDs corrompus (style NoSQL) -> 404 uniforme, jamais d'erreur 500."""
    register(client, "alice")
    r = client.get(f"/api/rooms/{room_id}")
    assert r.status_code == 404


@pytest.mark.parametrize("username", ["$ne", "$gt", "$where", "admin"])
def test_login_nosql_operator_returns_401(client, username) -> None:
    """Opérateurs NoSQL en login : l'utilisateur n'existe pas -> 401 uniforme."""
    r = client.post(
        "/api/auth/login",
        json={"username": username, "password": PASSWORD},
        headers={"X-CSRF-Token": _csrf(client)},
    )
    assert r.status_code == 401


def test_csrf_header_mismatch_forbidden(client) -> None:
    register(client, "alice")
    _csrf(client)  # pose un nouveau cookie CSRF
    r = client.post("/api/rooms", json={"name": "sala"}, headers={"X-CSRF-Token": "wrong"})
    assert r.status_code == 403


def test_csrf_missing_cookie_forbidden(anonymous) -> None:
    r = anonymous.post(
        "/api/auth/login",
        json={"username": "alice", "password": PASSWORD},
        headers={"X-CSRF-Token": "xyz"},
    )
    assert r.status_code == 403  # aucun cookie CSRF posé


def test_get_endpoints_do_not_require_csrf(client) -> None:
    register(client, "alice")
    assert client.get("/api/auth/me").status_code == 200
    assert client.get("/api/rooms").status_code == 200


def test_logout_requires_csrf(client) -> None:
    register(client, "alice")
    assert client.post("/api/auth/logout").status_code == 403
    r = client.post("/api/auth/logout", headers={"X-CSRF-Token": _csrf(client)})
    assert r.status_code == 204


def test_csrf_rotates_after_reauth(client) -> None:
    register(client, "alice")
    old_token = client.cookies.get("talk_csrf")
    assert old_token is not None

    csrf = _csrf(client)
    r = client.post(
        "/api/auth/login",
        json={"username": "alice", "password": PASSWORD},
        headers={"X-CSRF-Token": csrf},
    )
    assert r.status_code == 200

    new_token = client.cookies.get("talk_csrf")
    assert new_token is not None and new_token != old_token  # rotation

    # Ancien jeton (pré-volé) : inutilisable
    r = client.post("/api/rooms", json={"name": "sala"}, headers={"X-CSRF-Token": old_token})
    assert r.status_code == 403

    # Jeton courant : accepté
    r = client.post("/api/rooms", json={"name": "sala"}, headers={"X-CSRF-Token": new_token})
    assert r.status_code == 201
