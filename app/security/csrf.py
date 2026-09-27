"""Protection CSRF : double soumission de jeton.

- Requete anonyme : jeton stocke sous une cle derivee du jeton lui-meme
  (double submit cookie classique).
- Requete authentifiee : le jeton est lie a la session dans Redis, ce qui
  empeche la reutilisation d'un jeton vole sur une autre session.
"""

import hmac
import secrets

from fastapi import Response
from redis import Redis

from app.config import get_settings

CSRF_COOKIE = "csrf_token"
CSRF_HEADER = "X-CSRF-Token"


def _key(session_token: str | None, token: str) -> str:
    if session_token:
        return f"csrf:session:{session_token}"
    return f"csrf:anon:{token}"


def issue_csrf_token(redis: Redis, session_token: str | None) -> str:
    token = secrets.token_urlsafe(32)
    redis.setex(_key(session_token, token), get_settings().csrf_ttl_seconds, token)
    return token


def verify_csrf(
    redis: Redis,
    *,
    cookie_token: str | None,
    header_token: str | None,
    session_token: str | None,
) -> bool:
    if not cookie_token or not header_token:
        return False
    if not hmac.compare_digest(cookie_token, header_token):
        return False
    stored = redis.get(_key(session_token, cookie_token))
    return bool(stored) and hmac.compare_digest(stored, cookie_token)


def set_csrf_cookie(response: Response, token: str) -> None:
    settings = get_settings()
    response.set_cookie(
        CSRF_COOKIE,
        token,
        max_age=settings.csrf_ttl_seconds,
        httponly=False,
        secure=settings.cookie_secure,
        samesite=settings.cookie_samesite,
        path="/",
    )
