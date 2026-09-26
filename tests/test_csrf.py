"""Protection CSRF : bootstrap, absence, erreur et rejet entre sessions."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app.config import CSRF_COOKIE_NAME, CSRF_HEADER_NAME, SESSION_COOKIE_NAME
from tests.conftest import (
    VALID_PASSWORD,
    csrf_headers,
    register_user,
    set_cookie_attributes,
    unique_username,
)

MUTATIONS = [
    ("/auth/register", {"username": "x", "password": VALID_PASSWORD}),
    ("/auth/login", {"username": "x", "password": "y"}),
    ("/auth/logout", {}),
]


def test_csrf_endpoint_sets_both_cookies(client: TestClient) -> None:
    response = client.get("/auth/csrf")

    assert response.status_code == 200
    assert response.json()["csrf_token"]
    assert client.cookies.get(SESSION_COOKIE_NAME)
    assert client.cookies.get(CSRF_COOKIE_NAME) == response.json()["csrf_token"]


def test_session_cookie_is_httponly_and_csrf_cookie_is_not(client: TestClient) -> None:
    """La session porte le pouvoir et reste inaccessible au JS ; le CSRF doit
    rester lisible, sans quoi le double-submit est impossible."""
    response = client.get("/auth/csrf")

    session_cookie = set_cookie_attributes(response, SESSION_COOKIE_NAME)
    csrf_cookie = set_cookie_attributes(response, CSRF_COOKIE_NAME)

    assert "httponly" in session_cookie.lower()
    assert "samesite=lax" in session_cookie.lower()
    assert "httponly" not in csrf_cookie.lower()
    assert "samesite=lax" in csrf_cookie.lower()


def test_csrf_response_is_not_cacheable(client: TestClient) -> None:
    response = client.get("/auth/csrf")

    assert response.headers["cache-control"] == "no-store"


def test_csrf_is_idempotent(client: TestClient) -> None:
    """Un second appel renvoie le même jeton : un autre onglet ne casse rien."""
    first = client.get("/auth/csrf").json()["csrf_token"]
    second = client.get("/auth/csrf").json()["csrf_token"]

    assert first == second


@pytest.mark.parametrize(("path", "payload"), MUTATIONS)
def test_mutation_without_csrf_header_is_forbidden(
    client: TestClient, path: str, payload: dict[str, str]
) -> None:
    client.get("/auth/csrf")

    response = client.post(path, json=payload)

    assert response.status_code == 403


@pytest.mark.parametrize(("path", "payload"), MUTATIONS)
def test_mutation_with_wrong_csrf_token_is_forbidden(
    client: TestClient, path: str, payload: dict[str, str]
) -> None:
    client.get("/auth/csrf")

    response = client.post(
        path, json=payload, headers={CSRF_HEADER_NAME: "jeton-invente-000000000"}
    )

    assert response.status_code == 403


def test_csrf_token_from_another_session_is_forbidden(client: TestClient) -> None:
    """Le jeton est lu dans la session de l'appelant : celui d'autrui ne vaut rien."""
    stolen = client.get("/auth/csrf").json()["csrf_token"]

    # Jar vierge : le client devient la « victime », avec une session qui lui est propre.
    client.cookies.clear()
    own = csrf_headers(client)[CSRF_HEADER_NAME]
    assert own != stolen

    response = client.post(
        "/auth/register",
        json={"username": unique_username(), "password": VALID_PASSWORD},
        headers={CSRF_HEADER_NAME: stolen},
    )

    assert response.status_code == 403


def test_mutation_with_valid_csrf_succeeds(client: TestClient) -> None:
    response = client.post(
        "/auth/register",
        json={"username": unique_username(), "password": VALID_PASSWORD},
        headers=csrf_headers(client),
    )

    assert response.status_code == 201


def test_reads_do_not_require_csrf(client: TestClient) -> None:
    client.get("/auth/csrf")

    assert client.get("/health").status_code == 200
    assert client.get("/auth/me").status_code == 401


def test_csrf_rejected_without_any_session(client: TestClient) -> None:
    """Un jeton présenté sans cookie de session n'a aucune valeur attendue."""
    response = client.post(
        "/auth/login",
        json={"username": "quelquun", "password": "peu-importe"},
        headers={CSRF_HEADER_NAME: "jeton-sans-session-000000000000"},
    )

    assert response.status_code == 403


def test_csrf_token_survives_a_fresh_page_load(client: TestClient) -> None:
    register_user(client)
    token = client.get("/auth/csrf").json()["csrf_token"]

    response = client.post("/auth/logout", headers={CSRF_HEADER_NAME: token})

    assert response.status_code == 204
