"""Tests des clés publiques ECDH : publication, lecture, protection CSRF/auth."""

from conftest import register


def _csrf(client) -> str:
    r = client.get("/api/auth/csrf")
    assert r.status_code == 200
    return r.json()["csrf_token"]


def test_put_and_fetch_public_key(client) -> None:
    register(client, "alice")
    raw = "BMXKzWxLzQ..."
    r = client.put("/api/keys", json={"public_key": raw}, headers={"X-CSRF-Token": _csrf(client)})
    assert r.status_code == 204

    r = client.get("/api/keys/alice")
    assert r.status_code == 200
    assert r.json()["public_key"] == raw


def test_put_key_requires_csrf(client) -> None:
    register(client, "bob")
    r = client.put("/api/keys", json={"public_key": "x"})
    assert r.status_code == 403


def test_fetch_requires_auth(anonymous) -> None:
    assert anonymous.get("/api/keys/alice").status_code == 401


def test_fetch_unknown_user_404(client) -> None:
    register(client, "carol")
    r = client.get("/api/keys/nobody")
    assert r.status_code == 404
