"""En-têtes de sécurité HTTP ajoutés à toutes les réponses."""

from starlette.datastructures import MutableHeaders
from starlette.types import ASGIApp, Message, Receive, Scope, Send

SECURITY_HEADERS = {
    # Aucune ressource externe, aucun script/style inline : neutralise l'essentiel du XSS.
    "Content-Security-Policy": (
        "default-src 'none'; script-src 'self'; style-src 'self'; "
        "img-src 'self' data: blob:; media-src 'self' blob:; connect-src 'self'; "
        "font-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'"
    ),
    "X-Frame-Options": "DENY",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "Strict-Transport-Security": "max-age=63072000; includeSubDomains",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=(), payment=()",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
}


def apply_security_headers(headers: MutableHeaders, path: str) -> None:
    for name, value in SECURITY_HEADERS.items():
        headers.setdefault(name, value)
    if path.startswith("/api/"):
        headers.setdefault("Cache-Control", "no-store")


class SecurityHeadersMiddleware:
    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        async def send_with_headers(message: Message) -> None:
            if message["type"] == "http.response.start":
                apply_security_headers(MutableHeaders(scope=message), scope["path"])
            await send(message)

        await self.app(scope, receive, send_with_headers)
