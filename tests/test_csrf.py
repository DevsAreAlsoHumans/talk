from fastapi.testclient import TestClient

from tests.conftest import VALID_PASSWORD, VALID_USERNAME


def test_mutation_without_csrf_header_is_rejected(client: TestClient) -> None:
    response = client.post(
        "/auth/register",
        json={"username": VALID_USERNAME, "password": VALID_PASSWORD},
    )
    assert response.status_code == 403


def test_mutation_with_wrong_csrf_header_is_rejected(client: TestClient, csrf_headers) -> None:
    response = client.post(
        "/auth/register",
        json={"username": VALID_USERNAME, "password": VALID_PASSWORD},
        headers={"X-CSRF-Token": "jeton-fabrique"},
    )
    assert response.status_code == 403


def test_csrf_token_is_issued(client: TestClient) -> None:
    response = client.get("/auth/csrf")
    assert response.status_code == 200
    assert response.json()["csrf_token"] == client.cookies.get("csrf_token")
    cookie_header = response.headers["set-cookie"]
    assert "csrf_token=" in cookie_header
    assert "HttpOnly" not in cookie_header


def test_anonymous_csrf_token_is_single_use_per_token(client: TestClient, csrf_headers) -> None:
    first = client.post(
        "/auth/register",
        json={"username": VALID_USERNAME, "password": VALID_PASSWORD},
        headers=csrf_headers,
    )
    assert first.status_code == 201
    replay = client.post(
        "/auth/register",
        json={"username": "autre-utilisateur", "password": VALID_PASSWORD},
        headers=csrf_headers,
    )
    assert replay.status_code == 403


def test_session_csrf_token_is_bound_to_session(client: TestClient, registered) -> None:
    """Le jeton anonyme ne doit pas fonctionner une fois la session etablie."""
    anonymous_token = client.cookies.get("csrf_token")
    client.cookies.delete("session_id")
    assert anonymous_token
    response = client.post(
        "/auth/logout",
        headers={"X-CSRF-Token": anonymous_token},
    )
    assert response.status_code in (401, 403)


def test_password_hash_never_returned(client: TestClient, csrf_headers, registered) -> None:
    body = client.get("/auth/me").text
    assert "password_hash" not in body
    assert "scrypt$" not in body
