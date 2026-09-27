"""Salons (serveurs) et canaux, avec appartenance et roles.

Modele Redis :
- salon:<id>                  hash (id, name, owner_id, created_at)
- salon:<id>:members          set d'ids utilisateurs
- salon:<id>:roles            hash user_id -> role
- salon:<id>:channels         set d'ids canaux
- channel:<id>                hash (id, salon_id, name, topic, kind, created_at)
- channel:<id>:members        set d'ids (canaux prives uniquement)
- user:salons:<user_id>       set d'ids salons
"""

import uuid
from datetime import UTC, datetime

from redis import Redis

ROLE_OWNER = "owner"
ROLE_MODERATOR = "moderator"
ROLE_MEMBER = "member"
ROLE_RANK = {ROLE_MEMBER: 1, ROLE_MODERATOR: 2, ROLE_OWNER: 3}

KIND_TEXT = "text"
KIND_PRIVATE = "private"

DEFAULT_CHANNEL_NAME = "general"


def _salon_key(salon_id: str) -> str:
    return f"salon:{salon_id}"


def _members_key(salon_id: str) -> str:
    return f"salon:{salon_id}:members"


def _roles_key(salon_id: str) -> str:
    return f"salon:{salon_id}:roles"


def _channels_key(salon_id: str) -> str:
    return f"salon:{salon_id}:channels"


def _channel_key(channel_id: str) -> str:
    return f"channel:{channel_id}"


def _channel_members_key(channel_id: str) -> str:
    return f"channel:{channel_id}:members"


def _user_salons_key(user_id: str) -> str:
    return f"user:salons:{user_id}"


# --- Salons ---------------------------------------------------------------


def create_salon(redis: Redis, name: str, owner_id: str) -> dict:
    salon_id = uuid.uuid4().hex
    created_at = datetime.now(UTC)
    redis.hset(
        _salon_key(salon_id),
        mapping={
            "id": salon_id,
            "name": name,
            "owner_id": owner_id,
            "created_at": created_at.isoformat(),
        },
    )
    set_role(redis, salon_id, owner_id, ROLE_OWNER)
    create_channel(redis, salon_id, DEFAULT_CHANNEL_NAME, topic="Canal d'accueil", kind=KIND_TEXT)
    return get_salon(redis, salon_id) or {}


def get_salon(redis: Redis, salon_id: str) -> dict | None:
    data = redis.hgetall(_salon_key(salon_id))
    if not data:
        return None
    return {
        "id": data.get("id", salon_id),
        "name": data.get("name", ""),
        "owner_id": data.get("owner_id", ""),
        "created_at": data.get("created_at", ""),
    }


def salon_exists(redis: Redis, salon_id: str) -> bool:
    return bool(redis.exists(_salon_key(salon_id)))


def rename_salon(redis: Redis, salon_id: str, name: str) -> None:
    redis.hset(_salon_key(salon_id), "name", name)


def list_salons(redis: Redis, user_id: str) -> list[dict]:
    salons: list[dict] = []
    for salon_id in redis.smembers(_user_salons_key(user_id)):
        salon = get_salon(redis, salon_id)
        if salon is not None:
            salon["role"] = get_role(redis, salon_id, user_id) or ROLE_MEMBER
            salon["member_count"] = redis.scard(_members_key(salon_id))
            salons.append(salon)
    return sorted(salons, key=lambda item: item["created_at"])


def delete_salon(redis: Redis, salon_id: str) -> None:
    for channel_id in redis.smembers(_channels_key(salon_id)):
        delete_channel(redis, channel_id)
    for user_id in redis.smembers(_members_key(salon_id)):
        redis.srem(_user_salons_key(user_id), salon_id)
    redis.delete(
        _salon_key(salon_id),
        _members_key(salon_id),
        _roles_key(salon_id),
        _channels_key(salon_id),
    )


# --- Appartenance ---------------------------------------------------------


def get_role(redis: Redis, salon_id: str, user_id: str) -> str | None:
    if not redis.sismember(_members_key(salon_id), user_id):
        return None
    return redis.hget(_roles_key(salon_id), user_id)


def set_role(redis: Redis, salon_id: str, user_id: str, role: str) -> None:
    redis.sadd(_members_key(salon_id), user_id)
    redis.hset(_roles_key(salon_id), user_id, role)
    redis.sadd(_user_salons_key(user_id), salon_id)


def change_role(redis: Redis, salon_id: str, user_id: str, role: str) -> None:
    redis.hset(_roles_key(salon_id), user_id, role)


def remove_member(redis: Redis, salon_id: str, user_id: str) -> None:
    redis.srem(_members_key(salon_id), user_id)
    redis.hdel(_roles_key(salon_id), user_id)
    redis.srem(_user_salons_key(user_id), salon_id)
    for channel_id in redis.smembers(_channels_key(salon_id)):
        redis.srem(_channel_members_key(channel_id), user_id)


def list_member_ids(redis: Redis, salon_id: str) -> list[str]:
    return sorted(redis.smembers(_members_key(salon_id)))


# --- Canaux ---------------------------------------------------------------


def create_channel(
    redis: Redis, salon_id: str, name: str, *, topic: str = "", kind: str = KIND_TEXT
) -> dict:
    channel_id = uuid.uuid4().hex
    redis.hset(
        _channel_key(channel_id),
        mapping={
            "id": channel_id,
            "salon_id": salon_id,
            "name": name,
            "topic": topic,
            "kind": kind,
            "created_at": datetime.now(UTC).isoformat(),
        },
    )
    redis.sadd(_channels_key(salon_id), channel_id)
    return get_channel(redis, channel_id) or {}


def get_channel(redis: Redis, channel_id: str) -> dict | None:
    data = redis.hgetall(_channel_key(channel_id))
    if not data:
        return None
    return {
        "id": data.get("id", channel_id),
        "salon_id": data.get("salon_id", ""),
        "name": data.get("name", ""),
        "topic": data.get("topic", ""),
        "kind": data.get("kind", KIND_TEXT),
        "created_at": data.get("created_at", ""),
    }


def list_channels(redis: Redis, salon_id: str) -> list[dict]:
    channels = []
    for channel_id in redis.smembers(_channels_key(salon_id)):
        channel = get_channel(redis, channel_id)
        if channel is not None:
            channels.append(channel)
    return sorted(channels, key=lambda item: item["name"])


def update_channel(redis: Redis, channel_id: str, fields: dict) -> None:
    if fields:
        redis.hset(_channel_key(channel_id), mapping=fields)


def delete_channel(redis: Redis, channel_id: str) -> None:
    channel = get_channel(redis, channel_id)
    if channel is not None:
        redis.srem(_channels_key(channel["salon_id"]), channel_id)
    redis.delete(_channel_key(channel_id), _channel_members_key(channel_id))


def can_access_channel(redis: Redis, channel_id: str, user_id: str) -> dict | None:
    """Retourne le canal si l'utilisateur est membre du salon et visible."""
    channel = get_channel(redis, channel_id)
    if channel is None:
        return None
    if get_role(redis, channel["salon_id"], user_id) is None:
        return None
    if channel["kind"] == KIND_PRIVATE and not redis.sismember(
        _channel_members_key(channel_id), user_id
    ):
        return None
    return channel


def add_channel_member(redis: Redis, channel_id: str, user_id: str) -> None:
    redis.sadd(_channel_members_key(channel_id), user_id)


def remove_channel_member(redis: Redis, channel_id: str, user_id: str) -> None:
    redis.srem(_channel_members_key(channel_id), user_id)


def is_channel_member(redis: Redis, channel_id: str, user_id: str) -> bool:
    return bool(redis.sismember(_channel_members_key(channel_id), user_id))


def member_count(redis: Redis, salon_id: str) -> int:
    return int(redis.scard(_members_key(salon_id)))


def list_channel_member_ids(redis: Redis, channel_id: str) -> list[str]:
    return sorted(redis.smembers(_channel_members_key(channel_id)))
