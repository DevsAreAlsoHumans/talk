"""Sessions serveur : jeton opaque stocke dans Redis, cookie httpOnly."""

import json
import secrets
import time

from fastapi import Response
from redis import Redis

from app.config import get_settings

SESSION_COOKIE = "session_id"


def _session_key(token: str) -> str:
    return f"session:{token}"


def create_session(redis: Redis, user_id: str) -> str:
    token = secrets.token_urlsafe(32)
    payload = json.dumps({"user_id": user_id, "created_at": int(time.time())})
    redis.setex(_session_key(token), get_settings().session_ttl_seconds, payload)
    return token


def read_session(redis: Redis, token: str | None) -> dict | None:
    if not token:
        return None
    raw = redis.get(_session_key(token))
    if raw is None:
        return None
    try:
        data = json.loads(raw)
    except ValueError:
        return None
    return data if isinstance(data, dict) else None


def destroy_session(redis: Redis, token: str | None) -> None:
    if token:
        redis.delete(_session_key(token))


def set_session_cookie(response: Response, token: str) -> None:
    settings = get_settings()
    response.set_cookie(
        SESSION_COOKIE,
        token,
        max_age=settings.session_ttl_seconds,
        httponly=True,
        secure=settings.cookie_secure,
        samesite=settings.cookie_samesite,
        path="/",
    )


def clear_session_cookie(response: Response) -> None:
    response.delete_cookie(SESSION_COOKIE, path="/")
