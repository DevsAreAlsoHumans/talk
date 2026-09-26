import secrets

from fastapi import Cookie, Header, HTTPException, status

from app.config import settings
from app.db.redis_client import redis_client

SESSION_COOKIE_NAME = "session_id"
CSRF_COOKIE_NAME = "csrf_token"
CSRF_HEADER_NAME = "X-CSRF-Token"

_SESSION_KEY_PREFIX = "session:"


def _session_key(session_id: str) -> str:
    return f"{_SESSION_KEY_PREFIX}{session_id}"


async def create_session(user_id: str) -> tuple[str, str]:
    """Crée une session dans Redis et renvoie (session_id, csrf_token)."""
    session_id = secrets.token_urlsafe(32)
    csrf_token = secrets.token_urlsafe(32)
    key = _session_key(session_id)
    await redis_client.hset(key, mapping={"user_id": user_id, "csrf_token": csrf_token})
    await redis_client.expire(key, settings.session_ttl_seconds)
    return session_id, csrf_token


async def get_session(session_id: str) -> dict[str, str] | None:
    """Récupère une session depuis Redis, ou None si absente/expirée."""
    data = await redis_client.hgetall(_session_key(session_id))
    return data or None


async def delete_session(session_id: str) -> None:
    """Supprime une session de Redis (déconnexion)."""
    await redis_client.delete(_session_key(session_id))


async def _require_session(session_id: str | None) -> dict[str, str]:
    if session_id is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Non authentifié.")
    session = await get_session(session_id)
    if session is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Session invalide ou expirée."
        )
    return session


async def get_current_user_id(
    session_id: str | None = Cookie(default=None, alias=SESSION_COOKIE_NAME),
) -> str:
    """Dépendance FastAPI : renvoie l'id de l'utilisateur courant (401 si session invalide)."""
    session = await _require_session(session_id)
    return session["user_id"]


async def require_csrf(
    session_id: str | None = Cookie(default=None, alias=SESSION_COOKIE_NAME),
    csrf_header: str | None = Header(default=None, alias=CSRF_HEADER_NAME),
) -> None:
    """Dépendance FastAPI : vérifie le jeton CSRF double-submit sur une mutation authentifiée."""
    session = await _require_session(session_id)
    if not csrf_header or csrf_header != session.get("csrf_token"):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Jeton CSRF invalide.")
