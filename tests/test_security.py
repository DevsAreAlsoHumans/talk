from fastapi.testclient import TestClient

from app.security.sanitize import escape_html, sanitize_text
from tests.conftest import VALID_PASSWORD


def test_security_headers_present(client: TestClient) -> None:
    headers = client.get("/health").headers
    assert headers["X-Content-Type-Options"] == "nosniff"
    assert headers["X-Frame-Options"] == "DENY"
    assert headers["Referrer-Policy"] == "no-referrer"
    assert "default-src 'self'" in headers["Content-Security-Policy"]
    assert "frame-ancestors 'none'" in headers["Content-Security-Policy"]


def test_unknown_field_is_rejected(client: TestClient, csrf_headers) -> None:
    response = client.post(
        "/auth/register",
        json={
            "username": "augustin",
            "password": VALID_PASSWORD,
            "role": "admin",
        },
        headers=csrf_headers,
    )
    assert response.status_code == 422


def test_weak_password_is_rejected(client: TestClient, csrf_headers) -> None:
    response = client.post(
        "/auth/register",
        json={"username": "augustin", "password": "court"},
        headers=csrf_headers,
    )
    assert response.status_code == 422


def test_invalid_username_characters_are_rejected(client: TestClient, csrf_headers) -> None:
    response = client.post(
        "/auth/register",
        json={"username": "<script>alert(1)</script>", "password": VALID_PASSWORD},
        headers=csrf_headers,
    )
    assert response.status_code == 422


def test_no_sql_injection_in_username(client: TestClient, csrf_headers) -> None:
    response = client.post(
        "/auth/register",
        json={"username": "a'; DROP KEY user:index:x--", "password": VALID_PASSWORD},
        headers=csrf_headers,
    )
    assert response.status_code == 422


def test_sanitize_strips_control_characters() -> None:
    assert sanitize_text("salut\x00\n\x07", max_length=50) == "salut"


def test_sanitize_truncates() -> None:
    assert len(sanitize_text("a" * 100, max_length=10)) == 10


def test_escape_html_neutralizes_tags() -> None:
    assert "<script>" not in escape_html("<script>alert(1)</script>")
