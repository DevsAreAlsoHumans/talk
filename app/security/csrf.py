"""Protection CSRF : jeton « double-submit » signé, lié à la session, + contrôle d'origine.

Le middleware s'applique à TOUTES les requêtes POST/PUT/PATCH/DELETE (y compris
inscription et connexion) : impossible d'oublier une route.

Un jeton valide doit :
  1. être présent dans l'en-tête ``X-CSRF-Token`` ET dans le cookie CSRF, et les deux
     doivent être identiques (comparaison en temps constant) ;
  2. porter une signature HMAC-SHA256 valide, calculée avec la clé secrète du serveur
     sur (identifiant de session + nonce) : un jeton volé pour une autre session, ou
     forgé par un attaquant qui injecterait un cookie, est refusé.
Enfin l'en-tête ``Origin`` (ou à défaut ``Referer``) doit appartenir aux origines autorisées.
"""

import hashlib
import hmac
import secrets
from urllib.parse import urlsplit

from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Receive, Scope, Send

from app.config import Settings

CSRF_HEADER = "x-csrf-token"
UNSAFE_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})


def _sign(secret_key: str, session_id: str | None, nonce: str) -> str:
    message = f"{session_id or ''}:{nonce}".encode()
    return hmac.new(secret_key.encode(), message, hashlib.sha256).hexdigest()


def generate_csrf_token(secret_key: str, session_id: str | None) -> str:
    """Jeton lié à `session_id` (None pour les requêtes anonymes : inscription, connexion)."""
    nonce = secrets.token_urlsafe(24)
    return f"{nonce}.{_sign(secret_key, session_id, nonce)}"


def is_valid_csrf_token(secret_key: str, session_id: str | None, token: str | None) -> bool:
    if not token:
        return False
    nonce, separator, signature = token.partition(".")
    if not separator or not nonce or not signature:
        return False
    return hmac.compare_digest(signature, _sign(secret_key, session_id, nonce))


def origin_is_allowed(value: str | None, allowed_origins: list[str]) -> bool:
    """`value` est un en-tête Origin (« https://hote ») ou une URL de Referer."""
    if not value:
        return False
    parts = urlsplit(value)
    if not parts.scheme or not parts.netloc:
        return False
    return f"{parts.scheme}://{parts.netloc}" in allowed_origins


def request_origin_is_allowed(request: Request, allowed_origins: list[str]) -> bool:
    origin = request.headers.get("origin")
    if origin is not None:
        return origin_is_allowed(origin, allowed_origins)
    return origin_is_allowed(request.headers.get("referer"), allowed_origins)


class CSRFMiddleware:
    def __init__(self, app: ASGIApp, settings: Settings) -> None:
        self.app = app
        self.settings = settings

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or scope["method"] not in UNSAFE_METHODS:
            await self.app(scope, receive, send)
            return

        request = Request(scope)
        error = self._check(request)
        if error is not None:
            response = JSONResponse({"detail": error}, status_code=403)
            await response(scope, receive, send)
            return
        await self.app(scope, receive, send)

    def _check(self, request: Request) -> str | None:
        if not request_origin_is_allowed(request, self.settings.allowed_origins_list):
            return "Origine non autorisée"

        header_token = request.headers.get(CSRF_HEADER)
        cookie_token = request.cookies.get(self.settings.csrf_cookie_name)
        if not header_token or not cookie_token:
            return "Jeton CSRF manquant"
        if not hmac.compare_digest(header_token, cookie_token):
            return "Jeton CSRF invalide"

        session_id = request.cookies.get(self.settings.session_cookie_name)
        if not is_valid_csrf_token(self.settings.secret_key, session_id, header_token):
            return "Jeton CSRF invalide"
        return None
