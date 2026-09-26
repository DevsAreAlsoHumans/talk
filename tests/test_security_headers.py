"""En-têtes de sécurité présents sur toutes les réponses."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app.config import SESSION_COOKIE_NAME
from app.middleware import SECURITY_HEADERS
from tests.conftest import csrf_headers, set_cookie_attributes

PROTECTED_PATHS = ["/health", "/auth/csrf", "/auth/me", "/"]


@pytest.mark.parametrize("path", PROTECTED_PATHS)
def test_security_headers_present(client: TestClient, path: str) -> None:
    response = client.get(path)

    for header, value in SECURITY_HEADERS.items():
        assert response.headers[header] == value


def test_hsts_absent_over_http(client: TestClient) -> None:
    assert "strict-transport-security" not in client.get("/health").headers


def test_hsts_present_over_https(client: TestClient) -> None:
    """URL absolue : un second TestClient ouvrirait une seconde boucle asyncio,
    ce que `AsyncMongoClient` ne supporte pas."""
    response = client.get("https://testserver/health")

    assert response.headers["strict-transport-security"] == "max-age=31536000; includeSubDomains"


def test_content_security_policy_forbids_inline_script(client: TestClient) -> None:
    policy = client.get("/").headers["content-security-policy"]

    assert "script-src 'self'" in policy
    assert "unsafe-inline" not in policy
    assert "frame-ancestors 'none'" in policy


def test_server_header_is_not_disclosed(client: TestClient) -> None:
    assert "server" not in client.get("/health").headers


def test_headers_also_present_on_error_responses(client: TestClient) -> None:
    client.get("/auth/csrf")
    response = client.post("/auth/login", json={"username": "x", "password": "y"})

    assert response.status_code == 403
    assert response.headers["x-content-type-options"] == "nosniff"


def test_secure_flag_follows_the_environment(client: TestClient) -> None:
    """En développement le cookie ne doit pas être `Secure`, sinon le navigateur
    refuserait de le renvoyer sur une connexion en clair."""
    response = client.get("/auth/csrf")
    session_cookie = set_cookie_attributes(response, SESSION_COOKIE_NAME)

    assert "secure" not in session_cookie.lower()
    assert csrf_headers(client)
