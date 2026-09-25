"""Protection CSRF : double-submit cookie + vérification d'origine.

Deux défenses indépendantes sont appliquées à chaque mutation :

1. **Vérification d'origine** — l'en-tête `Origin` (à défaut `Referer`) doit
   désigner ce site. Un navigateur renseigne toujours `Origin` sur une requête
   de mutation et interdit au script attaquant de le falsifier.
2. **Double-submit cookie** — un jeton aléatoire doit être présent à la fois
   dans un cookie et dans l'en-tête `x-csrf-token`. Un site tiers peut faire
   envoyer le cookie par le navigateur, mais ne peut pas le lire pour
   reconstituer l'en-tête (politique de même origine).

Conformément à la recommandation OWASP, une requête dépourvue à la fois
d'`Origin` et de `Referer` est **refusée** plutôt qu'acceptée par défaut.
"""

import secrets
from urllib.parse import urlsplit

from fastapi import Request
from starlette.responses import JSONResponse

from app.config import settings

CSRF_COOKIE_NAME = "csrf_token"
CSRF_HEADER_NAME = "x-csrf-token"
SAFE_METHODS = {"GET", "HEAD", "OPTIONS", "WEBSOCKET"}


def generate_csrf_token() -> str:
    return secrets.token_hex(32)


def validate_csrf_token(cookie_token: str | None, header_token: str | None) -> bool:
    if not cookie_token or not header_token:
        return False
    # Comparaison à temps constant : pas de fuite par mesure du temps de réponse.
    return secrets.compare_digest(cookie_token, header_token)


def _normalize(url: str) -> str:
    """Réduit une URL à son origine : schéma + hôte + port."""
    parts = urlsplit(url)
    if not parts.scheme or not parts.netloc:
        return ""
    return f"{parts.scheme}://{parts.netloc}".lower()


def request_origin(request: Request) -> str | None:
    """Origine annoncée par le navigateur, via `Origin` puis `Referer`."""
    origin = request.headers.get("origin")
    if origin:
        # "null" est envoyé par une iframe cloisonnée ou un fichier local :
        # ce n'est pas une origine de confiance.
        if origin.lower() == "null":
            return None
        return _normalize(origin) or None

    referer = request.headers.get("referer")
    if referer:
        return _normalize(referer) or None

    return None


def allowed_origins(request: Request) -> set[str]:
    """Origines acceptées : l'URL publique configurée et celle de la requête."""
    allowed = {_normalize(settings.public_url)}

    # L'hôte visé par le navigateur. Une page tierce qui poste ici verra son
    # propre domaine dans `Origin`, mais cet hôte-ci dans `Host` : la
    # comparaison échoue, ce qui est exactement le but.
    host = request.headers.get("host")
    if host:
        scheme = request.headers.get("x-forwarded-proto") or request.url.scheme
        allowed.add(_normalize(f"{scheme}://{host}"))

    allowed.discard("")
    return allowed


def validate_origin(request: Request) -> bool:
    origin = request_origin(request)
    if origin is None:
        return False
    return origin in allowed_origins(request)


def _refuse(detail: str) -> JSONResponse:
    return JSONResponse(status_code=403, content={"detail": detail})


async def csrf_middleware(request: Request, call_next):
    if request.method.upper() not in SAFE_METHODS:
        if not validate_origin(request):
            return _refuse("Origine de la requête non autorisée")

        cookie_token = request.cookies.get(CSRF_COOKIE_NAME)
        header_token = request.headers.get(CSRF_HEADER_NAME)
        if not validate_csrf_token(cookie_token, header_token):
            return _refuse("CSRF token missing or invalid")

    response = await call_next(request)

    if CSRF_COOKIE_NAME not in request.cookies:
        csrf_token = generate_csrf_token()
        response.set_cookie(
            key=CSRF_COOKIE_NAME,
            value=csrf_token,
            # Lisible par le JS : c'est le principe du double-submit cookie.
            httponly=False,
            samesite="strict",
            # Secure dès que l'application est servie en HTTPS.
            secure=settings.public_url.startswith("https://"),
            path="/",
        )
    return response
