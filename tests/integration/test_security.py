"""Sécurité : CSRF, origine, injections, XSS, en-têtes, erreurs génériques, CORS."""

import pytest

from tests.helpers import e2e
from tests.helpers.actor import Actor

MUTATIONS = [
    ("POST", "/api/auth/logout", None),
    ("POST", "/api/rooms", {}),
    ("POST", "/api/rooms/00000000-0000-4000-8000-000000000000/members", {}),
    ("POST", "/api/rooms/00000000-0000-4000-8000-000000000000/messages", {}),
    ("PUT", "/api/rooms", {}),
    ("PATCH", "/api/rooms", {}),
    ("DELETE", "/api/rooms", None),
    ("POST", "/api/rooms/00000000-0000-4000-8000-000000000000/roles", {}),
    ("POST", "/api/friends/requests", {}),
    ("POST", "/api/friends/bob/accept", {}),
    ("POST", "/api/friends/bob/decline", {}),
    ("DELETE", "/api/friends/bob", None),
    ("POST", "/api/conversations", {}),
    ("POST", "/api/conversations/00000000-0000-4000-8000-000000000000/messages", {}),
]


# ---------- CSRF ----------


@pytest.mark.parametrize(("method", "path", "body"), MUTATIONS)
def test_every_mutation_without_csrf_token_is_forbidden(alice, method, path, body):
    response = alice.request(method, path, json=body, csrf=False)
    assert response.status_code == 403
    assert response.json() == {"detail": "Jeton CSRF manquant"}


def test_registration_and_login_are_also_csrf_protected(client):
    actor = Actor(client, e2e.Identity.create("alice"))
    assert (
        actor.post("/api/auth/register", actor.identity.registration_payload(), csrf=False).status_code == 403
    )
    actor.register()
    login = {"username": "alice", "auth_secret": actor.identity.auth_secret}
    assert actor.post("/api/auth/login", login, csrf=False).status_code == 403


def test_header_token_must_match_the_cookie(alice):
    other_token = Actor(alice.client, alice.identity)
    other_token.cookies = dict(alice.cookies)
    other_token.csrf_token = other_token.fetch_csrf()  # jeton valide mais différent du cookie de alice
    response = alice.post("/api/rooms", {}, headers={"X-CSRF-Token": other_token.csrf_token})
    assert response.status_code == 403
    assert response.json() == {"detail": "Jeton CSRF invalide"}


def test_forged_token_matching_a_cookie_planted_by_an_attacker_is_rejected(alice):
    """Attaque « cookie tossing » : l'attaquant fixe cookie ET en-tête à la même valeur forgée."""
    settings = alice.client.app.state.settings
    forged = "nonce-forge.0123456789abcdef"
    alice.cookies[settings.csrf_cookie_name] = forged
    response = alice.post("/api/rooms", {}, headers={"X-CSRF-Token": forged})
    assert response.status_code == 403


def test_token_from_another_session_is_rejected(alice, bob):
    """Un jeton valide pour la session de Bob ne fonctionne pas avec la session d'Alice."""
    settings = alice.client.app.state.settings
    alice.cookies[settings.csrf_cookie_name] = bob.csrf_token
    response = alice.post("/api/rooms", {}, headers={"X-CSRF-Token": bob.csrf_token})
    assert response.status_code == 403


def test_safe_methods_do_not_need_a_csrf_token(alice):
    assert alice.get("/api/rooms", csrf=False).status_code == 200


# ---------- Origine ----------


@pytest.mark.parametrize("origin", ["https://evil.example.com", "http://testserver.evil.com", "null"])
def test_mutation_from_a_foreign_origin_is_forbidden(alice, origin):
    response = alice.post("/api/rooms", {}, origin=origin)
    assert response.status_code == 403
    assert response.json() == {"detail": "Origine non autorisée"}


def test_mutation_without_origin_and_referer_is_forbidden(alice):
    assert alice.post("/api/rooms", {}, origin=None).status_code == 403


def test_referer_is_accepted_as_fallback_when_origin_is_absent(alice):
    good = alice.post("/api/rooms", {}, origin=None, headers={"Referer": "http://testserver/app"})
    bad = alice.post("/api/rooms", {}, origin=None, headers={"Referer": "https://evil.example.com/app"})
    assert good.status_code == 422  # a passé la barrière CSRF, refusé ensuite par la validation
    assert bad.status_code == 403


# ---------- Injections ----------


@pytest.mark.parametrize(
    "username",
    [{"$ne": None}, {"$gt": ""}, ["alice"], "alice:admin", "*", "alice\r\nSET x y", "user:*", "a" * 500],
)
def test_injection_attempts_in_login_are_rejected_by_validation(client, username):
    actor = Actor(client, e2e.Identity.create("alice"))
    actor.register()
    actor.fetch_csrf()
    response = actor.post(
        "/api/auth/login", {"username": username, "auth_secret": actor.identity.auth_secret}
    )
    assert response.status_code == 422
    assert "Traceback" not in response.text


def test_injection_in_registration_cannot_create_odd_keys(client, raw_redis):
    actor = Actor(client, e2e.Identity.create("alice"))
    actor.fetch_csrf()
    for username in ["admin:*", "x\nDEL *", "../root", "user:1"]:
        payload = {**actor.identity.registration_payload(), "username": username}
        assert actor.post("/api/auth/register", payload).status_code == 422
    assert list(raw_redis.scan_iter("*")) == []  # rien n'a été écrit en base


def test_extra_fields_cannot_escalate_privileges(alice):
    room_key = e2e.generate_room_key()
    payload = {
        "name": "salon",
        "wrapped_key": e2e.wrap_room_key(room_key, alice.identity.public_key),
        "owner_id": "00000000-0000-4000-8000-000000000000",
    }
    assert alice.post("/api/rooms", payload).status_code == 422


def test_validation_errors_never_echo_the_submitted_values(alice):
    response = alice.post("/api/rooms", {"name": "<script>alert('xss-secret')</script>", "wrapped_key": {}})
    assert response.status_code == 422
    assert "xss-secret" not in response.text
    assert set(response.json()) == {"detail", "fields"}


def test_room_names_cannot_carry_html(alice):
    wrapped = e2e.wrap_room_key(e2e.generate_room_key(), alice.identity.public_key)
    response = alice.post("/api/rooms", {"name": "<img src=x onerror=alert(1)>", "wrapped_key": wrapped})
    assert response.status_code == 422


# ---------- En-têtes, CORS, erreurs ----------


@pytest.mark.parametrize("path", ["/", "/api/health", "/api/rooms", "/inexistant"])
def test_security_headers_are_present_on_every_response(client, path):
    response = client.get(path)
    headers = response.headers
    assert "script-src 'self'" in headers["content-security-policy"]
    assert "frame-ancestors 'none'" in headers["content-security-policy"]
    assert "unsafe-inline" not in headers["content-security-policy"]
    # Les médias (images, vocaux) et avatars sont affichés via des URL `blob:` locales :
    # la CSP doit les autoriser, sinon le chiffrement ne serait jamais visible.
    assert "img-src 'self' data: blob:" in headers["content-security-policy"]
    assert "media-src 'self' blob:" in headers["content-security-policy"]
    assert headers["x-frame-options"] == "DENY"
    assert headers["x-content-type-options"] == "nosniff"
    assert headers["referrer-policy"] == "no-referrer"
    assert "max-age=" in headers["strict-transport-security"]
    assert headers["cross-origin-opener-policy"] == "same-origin"


def test_api_responses_are_not_cacheable(client):
    assert client.get("/api/health").headers["cache-control"] == "no-store"


def test_csrf_rejections_also_carry_security_headers(alice):
    response = alice.post("/api/rooms", {}, csrf=False)
    assert response.status_code == 403
    assert response.headers["x-frame-options"] == "DENY"


def test_no_cors_headers_are_ever_sent(client):
    response = client.options(
        "/api/rooms", headers={"Origin": "https://evil.example.com", "Access-Control-Request-Method": "POST"}
    )
    assert not any(name.lower().startswith("access-control-") for name in response.headers)
    simple = client.get("/api/health", headers={"Origin": "https://evil.example.com"})
    assert "access-control-allow-origin" not in simple.headers


def test_openapi_and_docs_are_not_exposed(client):
    for path in ["/docs", "/redoc", "/openapi.json"]:
        assert client.get(path).status_code == 404


def test_unexpected_errors_return_a_generic_500_without_stack_trace(settings, redis_backend, monkeypatch):
    from starlette.testclient import TestClient

    from app.main import create_app
    from app.repositories.users import UserRepository

    async def explode(self, username):
        raise RuntimeError("détail interne sensible: mot-de-passe-db")

    monkeypatch.setattr(UserRepository, "get_by_username", explode)
    app = create_app(settings, redis_factory=redis_backend.async_factory)

    with TestClient(app, raise_server_exceptions=False) as client:
        actor = Actor(client, e2e.Identity.create("alice"))
        actor.fetch_csrf()
        response = actor.post(
            "/api/auth/login", {"username": "alice", "auth_secret": actor.identity.auth_secret}
        )
    assert response.status_code == 500
    assert response.json() == {"detail": "Erreur interne"}
    assert "sensible" not in response.text
    assert "Traceback" not in response.text
    assert response.headers["x-frame-options"] == "DENY"


def test_wrong_method_and_unknown_route_give_generic_errors(client):
    for response in (client.get("/api/auth/login"), client.get("/api/nexiste-pas")):
        assert response.status_code in (404, 405)
        assert set(response.json()) == {"detail"}


def test_health_reports_unavailable_redis_generically(settings):
    from starlette.testclient import TestClient

    from app.main import create_app

    class BrokenRedis:
        async def ping(self):
            raise ConnectionError("redis://user:motdepasse@interne:6379 injoignable")

        def pubsub(self):
            return self

        async def subscribe(self, *_):
            return None

        async def get_message(self, **_):
            return None

        async def unsubscribe(self, *_):
            return None

        async def aclose(self):
            return None

    with TestClient(create_app(settings, redis_factory=BrokenRedis)) as client:
        response = client.get("/api/health")
    assert response.status_code == 503
    assert "motdepasse" not in response.text


# ---------- Frontend ----------


def test_frontend_is_served_without_inline_script(client):
    page = client.get("/")
    assert page.status_code == 200
    assert "<script>" not in page.text
    assert 'type="module"' in page.text
    assert client.get("/js/app.js").status_code == 200
    assert client.get("/../app/main.py").status_code in (404, 400)
