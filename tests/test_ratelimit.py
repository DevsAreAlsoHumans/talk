"""Rate limiting : anti force-brute sur /login et /register, sans DoS du reste."""

from starlette.testclient import TestClient

from app.ratelimit import MAX_REQUESTS, reset_rate_limits


def _login_attempt(client: TestClient, username: str, password: str) -> int:
    """Une tentative de login : jeton CSRF FRAIS à chaque fois (il est roté
    à chaque ré-authentification — sinon ce serait un 403 CSRF, pas un 429)."""
    csrf = client.get("/api/auth/csrf").json()["csrf_token"]
    return client.post(
        "/api/auth/login",
        json={"username": username, "password": password},
        headers={"X-CSRF-Token": csrf},
    ).status_code


def _register_attempt(client: TestClient, username: str) -> int:
    csrf = client.get("/api/auth/csrf").json()["csrf_token"]
    return client.post(
        "/api/auth/register",
        json={"username": username, "password": "P4ssw0rdX!"},
        headers={"X-CSRF-Token": csrf},
    ).status_code


def test_login_rate_limited_after_burst(client: TestClient) -> None:
    from conftest import register

    register(client, "alice")
    reset_rate_limits()

    statuses = [
        _login_attempt(client, "alice", "P4ssw0rdX!") for _ in range(MAX_REQUESTS + 2)
    ]
    # Les X premières passes (200), les suivantes sont bloquées en 429.
    assert statuses[:MAX_REQUESTS] == [200] * MAX_REQUESTS
    assert statuses[-2:] == [429, 429]


def test_register_rate_limited(client: TestClient) -> None:
    reset_rate_limits()

    ok = 0
    blocked = 0
    for i in range(MAX_REQUESTS + 3):
        code = _register_attempt(client, f"user{i}")
        if code == 201:
            ok += 1
        elif code == 429:
            blocked += 1
        else:
            raise AssertionError(f"comportement inattendu : HTTP {code}")
    assert ok == MAX_REQUESTS
    assert blocked == 3


def test_read_endpoints_not_rate_limited(client: TestClient) -> None:
    from conftest import register

    register(client, "alice")
    reset_rate_limits()

    for _ in range(MAX_REQUESTS * 3):
        assert client.get("/api/auth/me").status_code == 200


def test_window_resets(client: TestClient) -> None:
    from conftest import register

    register(client, "alice")
    reset_rate_limits()

    for _ in range(MAX_REQUESTS):
        assert _login_attempt(client, "alice", "P4ssw0rdX!") == 200
    assert _login_attempt(client, "alice", "P4ssw0rdX!") == 429

    reset_rate_limits()  # simule l'écoulement de la fenêtre glissante
    assert _login_attempt(client, "alice", "P4ssw0rdX!") == 200
