"""Middleware ASGI ajoutant les en-têtes de sécurité à toutes les réponses HTTP.

Écrit en ASGI pur plutôt qu'avec `BaseHTTPMiddleware` : cette dernier perturbe le
contexte d'exécution, ce qui serait risqué ici puisque l'application gère des
WebSockets.
"""

from __future__ import annotations

from starlette.datastructures import MutableHeaders
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from app.security import is_secure_request

CONTENT_SECURITY_POLICY = "; ".join(
    (
        "default-src 'self'",
        "script-src 'self'",
        "style-src 'self'",
        "img-src 'self' data:",
        "connect-src 'self'",
        "font-src 'self'",
        "base-uri 'none'",
        "form-action 'self'",
        "frame-ancestors 'none'",
        "object-src 'none'",
    )
)

STRICT_TRANSPORT_SECURITY = "max-age=31536000; includeSubDomains"

SECURITY_HEADERS = {
    "content-security-policy": CONTENT_SECURITY_POLICY,
    "referrer-policy": "no-referrer",
    "permissions-policy": "geolocation=(), microphone=(), camera=()",
    "x-content-type-options": "nosniff",
    "x-frame-options": "DENY",
    # 0 et non 1 : le filtre historique des navigateurs est source de failles.
    "x-xss-protection": "0",
}

# En-têtes ajoutés par le serveur, masqués pour ne rien divulguer.
_STRIPPED_HEADERS = frozenset({"server"})


class SecurityHeadersMiddleware:
    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        secure = is_secure_request(scope)

        async def send_with_security_headers(message: Message) -> None:
            if message["type"] == "http.response.start":
                headers = MutableHeaders(scope=message)
                for name in _STRIPPED_HEADERS:
                    if name in headers:
                        del headers[name]
                for name, value in SECURITY_HEADERS.items():
                    headers[name] = value
                if secure and "strict-transport-security" not in headers:
                    headers["strict-transport-security"] = STRICT_TRANSPORT_SECURITY
            await send(message)

        await self.app(scope, receive, send_with_security_headers)
