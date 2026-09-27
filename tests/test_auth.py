from fastapi.testclient import TestClient

from app.security.passwords import hash_password, verify_password
from tests.conftest import VALID_PASSWORD, VALID_USERNAME


def test_password_hash_is_salted_and_verifiable() -> None:
    first = hash_password(VALID_PASSWORD)
    second = hash_password(VALID_PASSWORD)
    assert first != second
    assert VALID_PASSWORD not in first
    assert verify_password(VALID_PASSWORD, first)
    assert not verify_password("mauvais-mot-de-passe", first)


def test_verify_rejects_malformed_hash() -> None:
    assert not verify_password(VALID_PASSWORD, "pas-un-hash")
    assert not verify_password(VALID_PASSWORD, "bcrypt$16384$8$1$00$00")


def test_register_sets_secure_session(client: TestClient, csrf_headers) -> None:
    response = client.post(
        "/auth/register",
        json={"username": VALID_USERNAME, "password": VALID_PASSWORD},
        headers=csrf_headers,
    )
    assert response.status_code == 201
    body = response.json()
    assert body["user"]["username"] == VALID_USERNAME
    assert "password" not in response.text
    set_cookie = response.headers["set-cookie"]
    assert "session_id=" in set_cookie
    assert "HttpOnly" in set_cookie
    assert "SameSite=lax" in set_cookie


def test_register_rejects_duplicate_username(client: TestClient, csrf_headers) -> None:
    first = client.post(
        "/auth/register",
        json={"username": VALID_USERNAME, "password": VALID_PASSWORD},
        headers=csrf_headers,
    )
    assert first.status_code == 201
    # L'inscription emet un nouveau jeton CSRF lie a la session : reutiliser
    # l'ancien jeton anonyme donnerait 403 au lieu du 409 attendu.
    fresh = client.get("/auth/csrf").json()["csrf_token"]
    duplicate = client.post(
        "/auth/register",
        json={"username": VALID_USERNAME, "password": VALID_PASSWORD},
        headers={"X-CSRF-Token": fresh},
    )
    assert duplicate.status_code == 409


def test_login_and_me(client: TestClient, csrf_headers, registered) -> None:
    client.post("/auth/logout", headers=registered)
    client.get("/auth/csrf")
    headers = {"X-CSRF-Token": client.cookies.get("csrf_token") or ""}
    login = client.post(
        "/auth/login",
        json={"username": VALID_USERNAME, "password": VALID_PASSWORD},
        headers=headers,
    )
    assert login.status_code == 200
    me = client.get("/auth/me")
    assert me.status_code == 200
    assert me.json()["username"] == VALID_USERNAME


def test_login_with_wrong_password(client: TestClient, csrf_headers, registered) -> None:
    client.post("/auth/logout", headers=registered)
    client.get("/auth/csrf")
    headers = {"X-CSRF-Token": client.cookies.get("csrf_token") or ""}
    response = client.post(
        "/auth/login",
        json={"username": VALID_USERNAME, "password": "mauvais-mot-de-passe"},
        headers=headers,
    )
    assert response.status_code == 401


def test_me_requires_session(client: TestClient) -> None:
    assert client.get("/auth/me").status_code == 401


def test_logout_invalidates_session(client: TestClient, registered) -> None:
    assert client.get("/auth/me").status_code == 200
    assert client.post("/auth/logout", headers=registered).status_code == 200
    assert client.get("/auth/me").status_code == 401


def test_login_rate_limited(client: TestClient, csrf_headers, registered) -> None:
    client.post("/auth/logout", headers=registered)
    for _ in range(12):
        client.get("/auth/csrf")
        headers = {"X-CSRF-Token": client.cookies.get("csrf_token") or ""}
        response = client.post(
            "/auth/login",
            json={"username": VALID_USERNAME, "password": "mauvais-mot-de-passe"},
            headers=headers,
        )
    assert response.status_code == 429
    assert "Retry-After" in response.headers
