"""Stockage des comptes. Mots de passe uniquement sous forme hachee."""

import uuid
from datetime import UTC, datetime

from redis import Redis

USER_PREFIX = "user:"
USERNAME_INDEX = "username:index:"


def _user_key(user_id: str) -> str:
    return f"{USER_PREFIX}{user_id}"


def create_user(redis: Redis, username: str, password_hash: str) -> dict | None:
    """Cree le compte. Retourne None si le pseudo est deja pris (race comprise)."""
    user_id = uuid.uuid4().hex
    created_at = datetime.now(UTC)
    payload = {
        "id": user_id,
        "username": username,
        "password_hash": password_hash,
        "created_at": created_at.isoformat(),
    }
    reserved = redis.set(f"{USERNAME_INDEX}{username}", user_id, nx=True)
    if not reserved:
        return None
    redis.hset(_user_key(user_id), mapping=payload)
    return payload


def get_by_username(redis: Redis, username: str) -> dict | None:
    user_id = redis.get(f"{USERNAME_INDEX}{username}")
    if not user_id:
        return None
    return get_by_id(redis, user_id)


def get_by_id(redis: Redis, user_id: str) -> dict | None:
    data = redis.hgetall(_user_key(user_id))
    if not data:
        return None
    return {
        "id": data.get("id", user_id),
        "username": data.get("username", ""),
        "password_hash": data.get("password_hash", ""),
        "created_at": data.get("created_at", ""),
    }
