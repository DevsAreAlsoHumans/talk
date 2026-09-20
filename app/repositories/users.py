"""Repository des utilisateurs.

Stockage Redis :
- ``user:{id}``      → JSON complet ``{id, username, password_hash, public_key, created_at}``
- ``username:{u}``   → ``id`` (index d'unicité du nom d'utilisateur, créé en SET NX)

La forme publique d'un utilisateur ne contient jamais le hash de mot de passe.
"""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime

from redis import Redis

USER_PREFIX = "user:"
USERNAME_INDEX_PREFIX = "username:"


def iso_utc_now() -> str:
    """Horodatage ISO 8601 en UTC (format imposé par le contrat)."""
    return datetime.now(UTC).isoformat()


def _user_key(user_id: str) -> str:
    return f"{USER_PREFIX}{user_id}"


def _username_index_key(username: str) -> str:
    return f"{USERNAME_INDEX_PREFIX}{username}"


def create_user(redis: Redis, username: str, password_hash: str, public_key: str) -> dict | None:
    """Crée un utilisateur et renvoie son enregistrement.

    Retourne ``None`` si le nom d'utilisateur est déjà pris (unicité garantie
    de façon atomique via ``SET NX``).
    """
    user_id = uuid.uuid4().hex
    taken = redis.set(_username_index_key(username), user_id, nx=True)
    if not taken:
        return None
    user = {
        "id": user_id,
        "username": username,
        "password_hash": password_hash,
        "public_key": public_key,
        "created_at": iso_utc_now(),
    }
    redis.set(_user_key(user_id), json.dumps(user))
    return user


def get_by_username(redis: Redis, username: str) -> dict | None:
    """Renvoie l'utilisateur identifié par son nom, ou ``None``."""
    user_id = redis.get(_username_index_key(username))
    if user_id is None:
        return None
    return get_by_id(redis, user_id)


def get_by_id(redis: Redis, user_id: str) -> dict | None:
    """Renvoie l'utilisateur identifié par son id, ou ``None``."""
    raw = redis.get(_user_key(user_id))
    if raw is None:
        return None
    return json.loads(raw)


def to_public(user: dict) -> dict:
    """Forme publique d'un utilisateur : id, username, clé publique, date."""
    return {
        "id": user["id"],
        "username": user["username"],
        "public_key": user["public_key"],
        "created_at": user["created_at"],
    }
