"""Dependances partagees : session courante et garde CSRF."""

from fastapi import Depends, HTTPException, Request, status
from redis import Redis

from app.db import get_redis
from app.repositories import users
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
    _user: dict | None = Depends(optional_user),
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
