"""Dependances partagees : session courante et garde CSRF."""

from fastapi import Depends, HTTPException, Request, status
from redis import Redis

from app.db import get_redis
from app.repositories import salons, users
from app.repositories.salons import ROLE_MODERATOR, ROLE_OWNER, ROLE_RANK
from app.security.csrf import CSRF_COOKIE, CSRF_HEADER, verify_csrf
from app.security.sessions import SESSION_COOKIE, read_session

CREDENTIALS_ERROR = HTTPException(
    status_code=status.HTTP_401_UNAUTHORIZED,
    detail="Authentification requise.",
    headers={"WWW-Authenticate": "Cookie"},
)


def current_user(request: Request, redis: Redis = Depends(get_redis)) -> dict:
    session = read_session(redis, request.cookies.get(SESSION_COOKIE))
    if session is None:
        raise CREDENTIALS_ERROR
    user = users.get_by_id(redis, str(session.get("user_id", "")))
    if user is None:
        raise CREDENTIALS_ERROR
    return user


def optional_user(request: Request, redis: Redis = Depends(get_redis)) -> dict | None:
    session = read_session(redis, request.cookies.get(SESSION_COOKIE))
    if session is None:
        return None
    return users.get_by_id(redis, str(session.get("user_id", "")))


def require_csrf(
    request: Request,
    redis: Redis = Depends(get_redis),
    user: dict | None = Depends(optional_user),
) -> None:
    """Verifie la double soumission du jeton CSRF sur toute mutation."""
    session_token = request.cookies.get(SESSION_COOKIE)
    if not verify_csrf(
        redis,
        cookie_token=request.cookies.get(CSRF_COOKIE),
        header_token=request.headers.get(CSRF_HEADER),
        session_token=session_token,
    ):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Jeton CSRF invalide ou manquant.",
        )


def salon_role(
    salon_id: str,
    redis: Redis = Depends(get_redis),
    user: dict = Depends(current_user),
) -> str:
    """Role de l'utilisateur dans le salon ; 404 si le salon lui est inconnu."""
    role = salons.get_role(redis, salon_id, user["id"])
    if role is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Salon introuvable.")
    return role


def _require_min_role(role: str, minimum: str) -> str:
    if ROLE_RANK[role] < ROLE_RANK[minimum]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Droits insuffisants pour cette action.",
        )
    return role


def salon_moderator(role: str = Depends(salon_role)) -> str:
    return _require_min_role(role, ROLE_MODERATOR)


def salon_owner(role: str = Depends(salon_role)) -> str:
    return _require_min_role(role, ROLE_OWNER)


def channel_access(
    channel_id: str, redis: Redis = Depends(get_redis), user: dict = Depends(current_user)
) -> dict:
    """Canau visible par l'utilisateur courant, sinon 404 (pas d'oracle d'existence)."""
    channel = salons.can_access_channel(redis, channel_id, user["id"])
    if channel is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Canal introuvable.")
    return channel
