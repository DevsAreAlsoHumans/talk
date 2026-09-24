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


async def get_current_user(
    request: Request,
    settings: Settings = Depends(get_settings),
    store: RedisStore = Depends(get_store),
) -> dict:
    token = request.cookies.get(settings.session_cookie_name)
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentification requise",
        )
    session = await store.get_session(hash_token(token))
    if session is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Session expirée ou invalide",
        )
    user = await store.get_user(session["user_id"])
    if user is None:
        await store.delete_session(hash_token(token))
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Session invalide",
        )
    return user


async def require_csrf(
    request: Request,
    settings: Settings = Depends(get_settings),
) -> None:
    cookie_token = request.cookies.get(settings.csrf_cookie_name)
    header_token = request.headers.get(CSRF_HEADER)
    if not cookie_token or not header_token or not constant_time_equal(cookie_token, header_token):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Jeton CSRF absent ou invalide",
        )
