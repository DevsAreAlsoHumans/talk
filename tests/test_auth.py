from conftest import TEST_ORIGIN, csrf_headers, identity_payload, register_user
from fastapi.testclient import TestClient


def test_register_session_and_logout(client, redis_client):
    result, registration_response = register_user(client, "alice", include_response=True)
    user = result["user"]

    me = client.get("/api/auth/me")
    assert me.status_code == 200
    assert me.json()["user"]["username"] == "alice"
    assert "password" not in me.text.lower()

    record = client.portal.call(redis_client.hgetall, f"talk:user:{user['id']}")
    assert record["password_hash"].startswith("$argon2id$")
    assert "mot de passe" not in record["password_hash"].lower()

    cookie_headers = registration_response.headers.get_list("set-cookie")
    assert any("talk_session=" in header and "HttpOnly" in header for header in cookie_headers)
    assert any("samesite=strict" in header.lower() for header in cookie_headers)

    logout = client.post(
        "/api/auth/logout",
        headers={"X-CSRF-Token": result["csrf_token"], "Origin": TEST_ORIGIN},
    )
    assert logout.status_code == 200
    assert client.get("/api/auth/me").status_code == 401


def test_duplicate_username_is_case_insensitive(client):
    register_user(client, "Alice")
    response = client.post(
        "/api/auth/register",
        headers=csrf_headers(client),
        json={
            "username": "ALICE",
            "display_name": "Autre",
            "password": "Un autre mot de passe robuste!",
            "identity_key": identity_payload(),
        },
    )
    assert response.status_code == 409
    assert response.json()["error"]["code"] == "conflict"


def test_login_failures_are_generic(app, client):
    register_user(client, "alice", "Mot de passe très sûr 2026!")
    client.post(
        "/api/auth/logout",
        headers=csrf_headers(client),
    )

    wrong_password = client.post(
        "/api/auth/login",
        headers=csrf_headers(client),
        json={"username": "alice", "password": "Mot de passe incorrect 2026!"},
    )
    unknown_user = client.post(
        "/api/auth/login",
        headers=csrf_headers(client),
        json={"username": "inconnu", "password": "Mot de passe incorrect 2026!"},
    )
    assert wrong_password.status_code == unknown_user.status_code == 401
    assert wrong_password.json()["error"]["message"] == unknown_user.json()["error"]["message"]


def test_identity_key_limit_is_enforced(client):
    register_user(client, "alice")
    for index in range(9):
        response = client.post(
            "/api/identity/keys",
            headers=csrf_headers(client),
            json=identity_payload(f"Device {index}"),
        )
        assert response.status_code == 201
    response = client.post(
        "/api/identity/keys",
        headers=csrf_headers(client),
        json=identity_payload("Device trop nombreux"),
    )
    assert response.status_code == 409
    assert "10 appareils" in response.json()["error"]["message"]


def test_user_search_uses_and_migrates_sorted_index(client, redis_client):
    register_user(client, "alice")
    client.portal.call(redis_client.delete, "talk:usernames:v2")
    client.portal.call(redis_client.sadd, "talk:usernames", "alice")

    response = client.get("/api/users", params={"query": "ali"})
    assert response.status_code == 200
    assert [user["username"] for user in response.json()["users"]] == ["alice"]
    index_type = client.portal.call(redis_client.type, "talk:usernames:v2")
    assert index_type == "zset"


def test_login_rotates_and_revokes_previous_session(client):
    register_user(client, "alice", "Mot de passe très sûr 2026!")
    old_session = client.cookies.get("talk_session")
    response = client.post(
        "/api/auth/login",
        headers=csrf_headers(client),
        json={"username": "alice", "password": "Mot de passe très sûr 2026!"},
    )
    assert response.status_code == 200
    new_session = client.cookies.get("talk_session")
    assert new_session != old_session

    client.cookies.clear()
    client.cookies.set("talk_session", old_session)
    assert client.get("/api/auth/me").status_code == 401


def test_validation_errors_do_not_echo_password(client):
    password = "mot-de-passe-a-ne-pas-echoir"
    response = client.post(
        "/api/auth/register",
        headers=csrf_headers(client),
        json={
            "username": "x",
            "display_name": "Alice",
            "password": password,
            "identity_key": identity_payload(),
        },
    )
    assert response.status_code == 422
    assert password not in response.text
    assert "input" not in response.text
    assert response.json()["error"]["code"] == "validation_error"


def test_secure_cookie_in_production(app, settings, redis_client):
    settings.environment = "production"
    settings.cookie_secure = True
    settings.allowed_origins = "https://testserver"
    with TestClient(app, base_url="https://testserver") as secure_client:
        result, response = register_user(
            secure_client,
            "secure",
            include_response=True,
            origin="https://testserver",
        )
        cookie_headers = response.headers.get_list("set-cookie")
        assert any("Secure" in header for header in cookie_headers)
        assert result["user"]["username"] == "secure"
