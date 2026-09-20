"""CRUD des sessions en Redis (stockage brut, sans la logique des cookies).

Chaque session est un JSON stocké sous ``session:{sid}`` :
``{"user_id": str | None, "csrf_token": str}`` avec un TTL configuré.
"""

from __future__ import annotations

import json

from redis import Redis

from app.config import settings

SESSION_PREFIX = "session:"


def session_key(sid: str) -> str:
    """Clé Redis d'une session."""
    return f"{SESSION_PREFIX}{sid}"


def get_session(redis: Redis, sid: str) -> dict | None:
    """Renvoie le contenu d'une session, ou ``None`` si inconnue/expirée."""
    raw = redis.get(session_key(sid))
    if raw is None:
        return None
    return json.loads(raw)


def save_session(redis: Redis, sid: str, user_id: str | None, csrf_token: str) -> None:
    """Persiste une session avec son TTL (réinitialisé à chaque rotation)."""
    payload = json.dumps({"user_id": user_id, "csrf_token": csrf_token})
    redis.set(session_key(sid), payload, ex=settings.SESSION_TTL)


def delete_session(redis: Redis, sid: str) -> None:
    """Supprime une session (logout / rotation)."""
    redis.delete(session_key(sid))
