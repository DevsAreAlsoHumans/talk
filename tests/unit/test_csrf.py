import pytest

from app.security import (
    allowed_origins,
    generate_csrf_token,
    request_origin,
    validate_csrf_token,
    validate_origin,
)


class FakeURL:
    def __init__(self, scheme="http"):
        self.scheme = scheme


class FakeRequest:
    """Requête minimale : seuls les en-têtes et le schéma sont consultés."""

    def __init__(self, headers=None, scheme="http"):
        self.headers = headers or {}
        self.url = FakeURL(scheme)


# ---------- Jeton double-submit ----------


def test_generate_csrf_token():
    token = generate_csrf_token()
    assert isinstance(token, str)
    assert len(token) == 64


def test_generate_csrf_token_is_random():
    assert generate_csrf_token() != generate_csrf_token()


def test_validate_csrf_matching():
    token = generate_csrf_token()
    assert validate_csrf_token(token, token) is True


def test_validate_csrf_mismatch():
    assert validate_csrf_token("token1", "token2") is False


def test_validate_csrf_empty():
    assert validate_csrf_token("", "") is False
    assert validate_csrf_token(None, None) is False


def test_validate_csrf_requires_both_sides():
    token = generate_csrf_token()
    assert validate_csrf_token(token, None) is False
    assert validate_csrf_token(None, token) is False


# ---------- Lecture de l'origine ----------


def test_origin_header_is_used_first():
    request = FakeRequest({"origin": "https://ronyme.app", "referer": "https://autre.example/page"})
    assert request_origin(request) == "https://ronyme.app"


def test_origin_is_reduced_to_scheme_and_host():
    request = FakeRequest({"origin": "https://Ronyme.app:443"})
    assert request_origin(request) == "https://ronyme.app:443"


def test_referer_is_used_when_origin_is_absent():
    request = FakeRequest({"referer": "https://ronyme.app/salons/123?x=1"})
    assert request_origin(request) == "https://ronyme.app"


def test_null_origin_is_not_trusted():
    """Une iframe cloisonnée ou un fichier local envoie `Origin: null`."""
    assert request_origin(FakeRequest({"origin": "null"})) is None


def test_no_origin_and_no_referer():
    assert request_origin(FakeRequest({})) is None


@pytest.mark.parametrize("value", ["", "pas-une-url", "/chemin/relatif"])
def test_malformed_origin_is_rejected(value):
    assert request_origin(FakeRequest({"origin": value})) is None


# ---------- Origines autorisées ----------


def test_request_host_is_allowed():
    request = FakeRequest({"host": "ronyme.app"}, scheme="https")
    assert "https://ronyme.app" in allowed_origins(request)


def test_forwarded_proto_is_honoured():
    """Derrière un reverse proxy TLS, le schéma vient de l'en-tête."""
    request = FakeRequest({"host": "ronyme.app", "x-forwarded-proto": "https"})
    assert "https://ronyme.app" in allowed_origins(request)


# ---------- Décision finale ----------


def test_same_origin_is_accepted():
    request = FakeRequest({"origin": "https://ronyme.app", "host": "ronyme.app"}, scheme="https")
    assert validate_origin(request) is True


def test_foreign_origin_is_rejected():
    """Le cas d'attaque : une page tierce poste vers notre hôte."""
    request = FakeRequest({"origin": "https://evil.example", "host": "ronyme.app"}, scheme="https")
    assert validate_origin(request) is False


def test_missing_origin_is_rejected():
    """Recommandation OWASP : bloquer plutôt qu'accepter par défaut."""
    request = FakeRequest({"host": "ronyme.app"}, scheme="https")
    assert validate_origin(request) is False


def test_lookalike_domain_is_rejected():
    request = FakeRequest({"origin": "https://ronyme.app.evil.example", "host": "ronyme.app"}, scheme="https")
    assert validate_origin(request) is False


def test_scheme_downgrade_is_rejected():
    request = FakeRequest({"origin": "http://ronyme.app", "host": "ronyme.app"}, scheme="https")
    assert validate_origin(request) is False
