"""Middlewares de sécurité HTTP : headers de protection des réponses.

CSP, X-Frame-Options, nosniff, referrer, permissions et — uniquement quand le
cookie est en mode ``Secure`` (HTTPS) — Strict-Transport-Security.
"""

from __future__ import annotations

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

# Headers envoyés sur toutes les réponses HTTP de l'application.
DEFAULT_SECURITY_HEADERS: dict[str, str] = {
    "Content-Security-Policy": (
        "default-src 'self'; script-src 'self'; style-src 'self'; "
        "img-src 'self' data:; connect-src 'self' ws: wss:; "
        "frame-ancestors 'none'; form-action 'self'; base-uri 'self'; object-src 'none'"
    ),
    "X-Frame-Options": "DENY",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "geolocation=(), microphone=(), camera=()",
    "X-XSS-Protection": "0",
}


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Ajoute les headers de sécurité à chaque réponse.

    ``cookie_secure`` (bool) active Header''Strict-Transport-Security'', ce qui
    n'a de sens qu'en HTTPS (cookie ``Secure``).
    """

    def __init__(self, app, cookie_secure: bool = False) -> None:
        super().__init__(app)
        headers = dict(DEFAULT_SECURITY_HEADERS)
        if cookie_secure:
            headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        self.security_headers: dict[str, str] = headers

    async def dispatch(self, request: Request, call_next) -> Response:
        response = await call_next(request)
        for name, value in self.security_headers.items():
            response.headers[name] = value
        return response
