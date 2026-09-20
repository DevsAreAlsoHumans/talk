"""Protection CSRF (token de session + vérification Origin/Referer).

Middleware global : toute mutation (POST/PUT/PATCH/DELETE) exige le header
``X-CSRF-Token`` égal au token de session, ET une origine (Origin/Referer)
dont l'hôte correspond à la requête. Le chemin ``/api/csrf`` est exclu du
contrôle de token mais son origine est tout de même vérifiée.

Les échecs renvoient toujours un 403 générique : ``{"detail": "..."}``.
"""

from __future__ import annotations

import hmac
from collections.abc import Iterable
from urllib.parse import urlparse

from fastapi import Request
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response

from app.db.redis import get_redis
from app.security.sessions import get_session

MUTATION_METHODS = {"POST", "PUT", "PATCH", "DELETE"}

_GENERIC_403 = {"detail": "Requête refusée"}


def origin_matches_host(request: Request) -> bool:
    """Vérifie que l''Origin''/''Referer'' (si présent) pointe vers notre hôte.

    Retourne ``True`` quand aucun header d'origine n'est fourni (conforme au
    contrat : contrôle uniquement "si présent").
    """
    origin = request.headers.get("origin")
    source = origin or request.headers.get("referer")
    if not source:
        return True
    try:
        netloc = urlparse(source).netloc
    except ValueError:
        return False
    return bool(netloc) and netloc == (request.url.netloc or "")


class CSRFMiddleware(BaseHTTPMiddleware):
    """Rejette les mutations sans token CSRF valide ou d'origine étrangère."""

    def __init__(self, app, exclude_paths: Iterable[str] | None = None) -> None:
        super().__init__(app)
        self.exclude_paths: set[str] = set(exclude_paths or ())

    async def dispatch(self, request: Request, call_next) -> Response:
        path = request.url.path
        is_mutation = request.method in MUTATION_METHODS
        is_excluded = path in self.exclude_paths

        # L'origine est vérifiée sur les mutations ET sur les chemins exclus
        # (ex. /api/csrf), afin d'empêcher un site tiers de créer une session.
        if (is_mutation or is_excluded) and not origin_matches_host(request):
            return JSONResponse(status_code=403, content=_GENERIC_403)

        if is_mutation and not is_excluded:
            header_token = request.headers.get("x-csrf-token")
            if header_token is None:
                return JSONResponse(status_code=403, content=_GENERIC_403)
            session = get_session(get_redis(request), request)
            if session is None or not hmac.compare_digest(header_token, session["csrf_token"]):
                return JSONResponse(status_code=403, content=_GENERIC_403)

        return await call_next(request)
