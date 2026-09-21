"""Parcours d'authentification : inscription, connexion, session, déconnexion."""

from tests.helpers import e2e
from tests.helpers.actor import Actor


def new_actor(client, name="alice"):
    return Actor(client, e2e.Identity.create(name))


def test_register_then_login_then_me(client):
    actor = new_actor(client)
    response = actor.register()
    assert response.status_code == 201
    assert set(response.json()) == {"id", "username", "public_key"}

    login = actor.login()
    assert login.status_code == 200
    body = login.json()
    assert body["user"]["username"] == "alice"
    assert body["csrf_token"]

    me = actor.get("/api/auth/me")
    assert me.status_code == 200
    assert me.json()["username"] == "alice"


def test_encrypted_private_key_returned_at_login_can_be_decrypted_by_its_owner(client):
    actor = new_actor(client)
    actor.register()
    body = actor.login().json()
    restored = e2e.decrypt_private_key(body["user"]["encrypted_private_key"], actor.identity.wrap_key)
    assert e2e.public_key_b64(restored.public_key()) == actor.identity.public_key


def test_duplicate_username_is_refused(client):
    first = new_actor(client)
    assert first.register().status_code == 201
    second = new_actor(client)
    response = second.register()
    assert response.status_code == 409


def test_login_with_wrong_secret_or_unknown_user_gives_the_same_generic_error(client):
    actor = new_actor(client)
    actor.register()
    actor.fetch_csrf()

    wrong = actor.post("/api/auth/login", {"username": "alice", "auth_secret": e2e.b64(b"x" * 32)})
    unknown = actor.post("/api/auth/login", {"username": "personne", "auth_secret": e2e.b64(b"x" * 32)})
    assert wrong.status_code == unknown.status_code == 401
    assert wrong.json() == unknown.json() == {"detail": "Identifiants invalides"}
    assert "set-cookie" not in wrong.headers


def test_protected_routes_require_a_session(client):
    anonymous = new_actor(client)
    anonymous.fetch_csrf()
    for method, path in [("GET", "/api/auth/me"), ("GET", "/api/rooms"), ("GET", "/api/users/alice")]:
        assert anonymous.request(method, path).status_code == 401
    assert anonymous.post("/api/rooms", {}).status_code == 401


def test_logout_destroys_the_session_server_side(client, alice):
    stolen_cookies = dict(alice.cookies)
    assert alice.post("/api/auth/logout").status_code == 204
    assert alice.get("/api/auth/me").status_code == 401

    # Même en rejouant l'ancien cookie de session, la session est morte.
    alice.cookies = stolen_cookies
    assert alice.get("/api/auth/me").status_code == 401


def test_login_rotates_the_session(client):
    actor = new_actor(client)
    actor.register()
    actor.login()
    old_session = actor.cookies[client.app.state.settings.session_cookie_name]

    actor.login()  # nouvelle connexion en présentant l'ancien cookie
    new_session = actor.cookies[client.app.state.settings.session_cookie_name]
    assert new_session != old_session

    replay = new_actor(client)
    replay.cookies = {client.app.state.settings.session_cookie_name: old_session}
    assert replay.get("/api/auth/me").status_code == 401


def test_session_cookie_flags(settings, redis_backend):
    from starlette.testclient import TestClient

    from app.main import create_app

    secure_settings = settings.model_copy(update={"cookie_secure": True})
    with TestClient(create_app(secure_settings, redis_factory=redis_backend.async_factory)) as client:
        actor = new_actor(client)
        actor.register()
        actor.fetch_csrf()
        response = actor.post(
            "/api/auth/login", {"username": "alice", "auth_secret": actor.identity.auth_secret}
        )
        assert response.status_code == 200
        cookies = {header.split("=")[0]: header for header in response.headers.get_list("set-cookie")}
        session_header = cookies["__Host-session"].lower()
        assert "httponly" in session_header
        assert "secure" in session_header
        assert "samesite=strict" in session_header
        assert "path=/" in session_header
        assert "domain" not in session_header
        assert "httponly" in cookies["__Host-csrf"].lower()


def test_login_is_rate_limited(settings, redis_backend):
    from starlette.testclient import TestClient

    from app.main import create_app

    limited = settings.model_copy(update={"login_account_limit": 3})
    with TestClient(create_app(limited, redis_factory=redis_backend.async_factory)) as client:
        actor = new_actor(client)
        actor.register()
        actor.fetch_csrf()
        bad = {"username": "alice", "auth_secret": e2e.b64(b"x" * 32)}
        statuses = [actor.post("/api/auth/login", bad).status_code for _ in range(5)]
        assert statuses == [401, 401, 401, 429, 429]
        # Même le bon secret est bloqué pendant la fenêtre : le blocage ne dépend pas de la réponse.
        good = {"username": "alice", "auth_secret": actor.identity.auth_secret}
        blocked = actor.post("/api/auth/login", good)
        assert blocked.status_code == 429
        assert "retry-after" in blocked.headers


def test_registration_is_rate_limited(settings, redis_backend):
    from starlette.testclient import TestClient

    from app.main import create_app

    limited = settings.model_copy(update={"register_limit": 2})
    with TestClient(create_app(limited, redis_factory=redis_backend.async_factory)) as client:
        statuses = [new_actor(client, f"user{i}").register().status_code for i in range(4)]
        assert statuses == [201, 201, 429, 429]


def test_passwords_are_stored_hashed_with_argon2(client, alice, raw_redis):
    user = raw_redis.hgetall(f"user:{alice.user_id}")
    assert user["password_hash"].startswith("$argon2id$")
    assert alice.identity.auth_secret not in user["password_hash"]
    assert alice.identity.password not in " ".join(user.values())
