"""Middleware : headers de durcissement HTTP sur CHAQUE réponse.

Politiques déclaratives + CSP restrictive. Le navigateur applique, le serveur
n'a pas à « espérer » que le client soit sage.
"""

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

# CSP minimale : pas de scripts externes, pas d'inline, pas d'objets embarqués.
# Le front (Vanilla JS) étant servi par le même origin, 'self' suffit.
_CSP = (
    "default-src 'self'; "
    "script-src 'self'; "
    "style-src 'self'; "
    "img-src 'self' data:; "
    "connect-src 'self' ws: wss:; "  # autorise les WebSockets du chat
    "object-src 'none'; "
    "base-uri 'self'; "
    "frame-ancestors 'none'; "
    "form-action 'self'"
)


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next) -> Response:
        response = await call_next(request)
        response.headers["Content-Security-Policy"] = _CSP
        # Nosniff : interdit au navigateur de deviner le MIME d'un .js mal formé
        response.headers["X-Content-Type-Options"] = "nosniff"
        # DENY : notre app n'est jamais framable (anti clickjacking)
        response.headers["X-Frame-Options"] = "DENY"
        # Ne jamais fuiter l'URL (tokens) via le Referer vers des tiers
        response.headers["Referrer-Policy"] = "no-referrer"
        # Navigateurs récents : désactive le "mimétisme de page" IE/Edge
        response.headers["X-XSS-Protection"] = "0"
        return response
