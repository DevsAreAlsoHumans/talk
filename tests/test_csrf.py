from conftest import TEST_ORIGIN, register_user


def test_mutation_requires_csrf_header(client):
    response = client.post(
        "/api/auth/register",
        json={
            "username": "alice",
            "display_name": "Alice",
            "password": "Mot de passe très sûr 2026!",
            "identity_key": {
                "key_id": "c771c2bd-29d2-4c97-936f-f17d11fbba3e",
                "device_name": "Test",
                "public_key": {
                    "kty": "RSA",
                    "alg": "RSA-OAEP-256",
                    "n": "A" * 384,
                    "e": "AQAB",
                    "ext": True,
                    "key_ops": ["encrypt"],
                },
            },
        },
    )
    assert response.status_code == 403
    assert response.json()["error"]["code"] == "forbidden"


def test_csrf_token_is_bound_to_current_session(client):
    result = register_user(client, "alice")
    session_cookie = client.cookies.get("talk_session")
    client.cookies.clear()
    client.cookies.set("talk_session", session_cookie)
    client.cookies.set("talk_csrf", "forged-token")
    forged = client.post(
        "/api/identity/keys",
        headers={"X-CSRF-Token": "forged-token", "Origin": TEST_ORIGIN},
        json=result["user"]["identity_keys"][0],
    )
    assert forged.status_code == 403
    assert "session" in forged.json()["error"]["message"].lower()


def test_foreign_origin_is_rejected(client):
    token = client.get("/api/auth/csrf").json()["csrf_token"]
    response = client.post(
        "/api/auth/login",
        headers={"X-CSRF-Token": token, "Origin": "https://attaquant.example"},
        json={"username": "alice", "password": "Mot de passe incorrect 2026!"},
    )
    assert response.status_code == 403
