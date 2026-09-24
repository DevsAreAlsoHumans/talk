import time
from typing import Optional

from fastapi import Depends, HTTPException, Request, status
from redis.asyncio import Redis

from app.config import Settings
from app.security import constant_time_equal, hash_token
from app.storage import RedisStore

CSRF_HEADER = "X-CSRF-Token"


def get_settings(request: Request) -> Settings:
    return request.app.state.settings


def get_redis(request: Request) -> Redis:
    return request.app.state.redis


def get_store(redis: Redis = Depends(get_redis)) -> RedisStore:
    return request_store(redis)


def request_store(redis: Redis) -> RedisStore:
    return RedisStore(redis)


async def get_optional_session(
    request: Request,
    settings: Settings = Depends(get_settings),
    store: RedisStore = Depends(get_store),
) -> Optional[tuple[str, dict]]:
    token = request.cookies.get(settings.session_cookie_name)
    if not token:
        return None
    token_hash = hash_token(token)
    session = await store.get_session(token_hash)
    if session is None:
        return None
    return token_hash, session


async def get_current_user(
    session_context: Optional[tuple[str, dict]] = Depends(get_optional_session),
    store: RedisStore = Depends(get_store),
) -> dict:
    if session_context is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentification requise",
        )
    token_hash, session = session_context
    user = await store.get_user(session["user_id"])
    if user is None:
        await store.delete_session(token_hash)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Session invalide",
        )
    return user


async def require_csrf(
    request: Request,
    settings: Settings = Depends(get_settings),
    session_context: Optional[tuple[str, dict]] = Depends(get_optional_session),
) -> None:
    origin = request.headers.get("origin")
    if origin and origin not in settings.origin_list:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Origine de requête non autorisée",
        )
    cookie_token = request.cookies.get(settings.csrf_cookie_name)
    header_token = request.headers.get(CSRF_HEADER)
    if not cookie_token or not header_token or not constant_time_equal(cookie_token, header_token):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Jeton CSRF absent ou invalide",
        )
    if session_context is not None:
        session = session_context[1]
        if not constant_time_equal(session["csrf_token"], cookie_token):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Jeton CSRF non lié à la session",
            )
        if int(session.get("csrf_expires_at", 0)) <= int(time.time()):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Jeton CSRF expiré",
            )
