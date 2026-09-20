"""Dépendances partagées (authn / CSRF) — injectables, donc testables."""

from typing import Annotated

from fastapi import Depends, HTTPException, Request, status

from .db import Database, get_db
from .models import UserPublic, _UserOut
from .security import constant_time_eq, cookie_params, verify_session_token

SESSION_COOKIE = "talk_session"
CSRF_COOKIE = "talk_csrf"
# Header requis pour TOUTE requête de mutation : le cookie CSRF seul ne suffit
# pas — l'attaquant doit connaître sa valeur (double-submit à temps constant).
CSRF_HEADER = "X-CSRF-Token"

DbDep = Annotated[Database, Depends(get_db)]


def _read_session_token(request: Request) -> str | None:
    return request.cookies.get(SESSION_COOKIE)


async def get_current_user(
    request: Request,
    db: DbDep,
) -> UserPublic:
    """Authentifie : cookie de session signé -> utilisateur en base."""
    token = _read_session_token(request)
    user = None
    if token:
        session = verify_session_token(token)
        if session:
            found = await db.get_user_by_id(session["uid"])
            if found:
                user = _UserOut.of(found)
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentification requise",
        )
    return user


def get_csrf_cookie_params(http_only: bool = False):
    return cookie_params(http_only=http_only)


def require_csrf(request: Request) -> None:
    """Protection CSRF de type double-submit.

    Principe : un cookie `talk_csrf` (lisible en JS pour être renvoyé) + une
    vérification serveur à temps constant. SameSite=strict bloque l'envoi
    cross-site du cookie, et ce test bloque tout envoi « forgé » même si une
    brèche CORS contournait le navigateur.
    """
    cookie = request.cookies.get(CSRF_COOKIE)
    header = request.headers.get(CSRF_HEADER)
    if not cookie or not header or not constant_time_eq(cookie, header):
        raise HTTPException(status_code=403, detail="Échec du contrôle CSRF")
