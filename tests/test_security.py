"""Tests de sécurité : hachage, CSRF, origine, headers, erreurs."""

from app.security import check_password, hash_password
from tests.conftest import ORIGIN, signup


def test_hash_is_argon2_and_not_plain():
    password_hash = hash_password("motdepasse123")
    assert password_hash.startswith("$argon2id$")
    assert "motdepasse123" not in password_hash
    assert check_password("motdepasse123", password_hash)


def test_wrong_password_is_rejected():
    assert not check_password("mauvais-mdp", hash_password("motdepasse123"))


def test_same_password_gives_different_hashes():
    assert hash_password("motdepasse123") != hash_password("motdepasse123")


def test_unknown_or_broken_hash_is_rejected():
    assert not check_password("compte-inexistant", None)
    assert not check_password("motdepasse123", "pas-un-hash")


def test_security_headers_on_every_response(client):
    for path in ["/", "/api/csrf", "/static/app.js"]:
        headers = client.get(path).headers
        assert "default-src 'none'" in headers["content-security-policy"]
        assert headers["x-frame-options"] == "DENY"
        assert headers["x-content-type-options"] == "nosniff"
        assert headers["referrer-policy"] == "same-origin"
        assert headers["strict-transport-security"].startswith("max-age=")
        assert headers["cross-origin-opener-policy"] == "same-origin"


def test_no_cors_header(client):
    response = client.get("/api/csrf", headers={"Origin": "https://site-pirate.example"})
    assert "access-control-allow-origin" not in response.headers


def test_cookies_are_httponly_and_samesite(client):
    session_cookie = signup(client).headers["set-cookie"].lower()
    csrf_cookie = client.get("/api/csrf").headers["set-cookie"].lower()
    for cookie in [session_cookie, csrf_cookie]:
        assert "httponly" in cookie and "samesite=strict" in cookie


def test_csrf_header_missing(client):
    del client.headers["X-CSRF-Token"]
    assert signup(client).status_code == 403


def test_csrf_header_wrong(client):
    client.headers["X-CSRF-Token"] = "mauvais"
    assert signup(client).status_code == 403


def test_csrf_cookie_missing(client):
    client.cookies.clear()
    assert signup(client).status_code == 403


def test_foreign_origin_is_rejected(client):
    client.headers["Origin"] = "https://site-pirate.example"
    assert signup(client).status_code == 403


def test_missing_origin_and_referer_is_rejected(client):
    del client.headers["Origin"]
    assert signup(client).status_code == 403


def test_same_site_referer_is_accepted(client):
    del client.headers["Origin"]
    client.headers["Referer"] = ORIGIN + "/"
    assert signup(client).status_code == 200


def test_lookalike_referer_is_rejected(client):
    del client.headers["Origin"]
    client.headers["Referer"] = ORIGIN + ".pirate.example/"
    assert signup(client).status_code == 403


def test_validation_error_is_generic(client):
    response = client.post("/api/signup", json={"username": "a", "password": "court"})
    assert response.status_code == 422
    assert response.json() == {"detail": "Données invalides"}


def test_server_error_is_generic(client, monkeypatch):
    async def broken(*args, **kwargs):
        raise RuntimeError("secret interne")

    monkeypatch.setattr("fakeredis.aioredis.FakeRedis.get", broken)
    client.cookies.set("session", "x")
    response = client.get("/api/me")
    assert response.status_code == 500
    assert response.json() == {"detail": "Erreur interne"}
    assert "secret interne" not in response.text


def test_api_docs_are_disabled(client):
    for path in ["/docs", "/redoc", "/openapi.json"]:
        assert client.get(path).status_code == 404
