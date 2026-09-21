"""Repository des salons.

Stockage Redis :
- ``room:{id}``               → JSON ``{id, name, owner_id, created_at}``
- ``room:{id}:members``       → set des ids membres
- ``room:{id}:keys``          → hash ``{target_user_id: wrapped_key}`` (clé de salon enveloppée)
- ``user:{id}:rooms``         → set des salons de l'utilisateur (index de listing)
"""

from __future__ import annotations

import json
import uuid

from redis import Redis

from app.repositories import users

ROOM_PREFIX = "room:"
MEMBERS_SUFFIX = ":members"
KEYS_SUFFIX = ":keys"
USER_ROOMS_PREFIX = "user:"
USER_ROOMS_SUFFIX = ":rooms"
#: Préfixe des compteurs de présence Redis (``presence:count:{user_id}``).
PRESENCE_COUNT_PREFIX = "presence:count:"


def _room_key(room_id: str) -> str:
    return f"{ROOM_PREFIX}{room_id}"


def _members_key(room_id: str) -> str:
    return f"{ROOM_PREFIX}{room_id}{MEMBERS_SUFFIX}"


def _keys_key(room_id: str) -> str:
    return f"{ROOM_PREFIX}{room_id}{KEYS_SUFFIX}"


def _user_rooms_key(user_id: str) -> str:
    return f"{USER_ROOMS_PREFIX}{user_id}{USER_ROOMS_SUFFIX}"


def create_room(redis: Redis, name: str, owner_id: str) -> dict:
    """Crée un salon dont le créateur devient premier membre."""
    room_id = uuid.uuid4().hex
    room = {
        "id": room_id,
        "name": name,
        "owner_id": owner_id,
        "created_at": users.iso_utc_now(),
    }
    pipe = redis.pipeline()
    pipe.set(_room_key(room_id), json.dumps(room))
    pipe.sadd(_members_key(room_id), owner_id)
    pipe.sadd(_user_rooms_key(owner_id), room_id)
    pipe.execute()
    return room


def get_room(redis: Redis, room_id: str) -> dict | None:
    """Renvoie le salon, ou ``None`` s'il n'existe pas."""
    raw = redis.get(_room_key(room_id))
    if raw is None:
        return None
    return json.loads(raw)


def add_member(redis: Redis, room_id: str, user_id: str) -> None:
    """Ajoute un membre au salon (côté salon ET côté index utilisateur)."""
    pipe = redis.pipeline()
    pipe.sadd(_members_key(room_id), user_id)
    pipe.sadd(_user_rooms_key(user_id), room_id)
    pipe.execute()


def remove_member(redis: Redis, room_id: str, user_id: str) -> None:
    """Retire un membre du salon et de l'index utilisateur."""
    pipe = redis.pipeline()
    pipe.srem(_members_key(room_id), user_id)
    pipe.srem(_user_rooms_key(user_id), room_id)
    pipe.execute()


def is_member(redis: Redis, room_id: str, user_id: str) -> bool:
    """L'utilisateur est-il membre du salon ?"""
    return redis.sismember(_members_key(room_id), user_id) == 1


def list_for_user(redis: Redis, user_id: str) -> list[dict]:
    """Salons dont l'utilisateur est membre, triés par création."""
    room_ids = redis.smembers(_user_rooms_key(user_id))
    rooms = []
    for room_id in room_ids:
        room = get_room(redis, room_id)
        if room is not None:
            rooms.append(room)
    rooms.sort(key=lambda r: r["created_at"])
    return rooms


def get_member_ids(redis: Redis, room_id: str) -> list[str]:
    """Ids des membres du salon."""
    return list(redis.smembers(_members_key(room_id)))


def _is_online(redis: Redis, user_id: str) -> bool:
    """Un utilisateur est-il en ligne (au moins un onglet WebSocket connecté) ?"""
    return int(redis.get(PRESENCE_COUNT_PREFIX + user_id) or 0) > 0


def list_members(redis: Redis, room_id: str) -> list[dict]:
    """Membres du salon sous forme publique ``{id, username, public_key, online}``."""
    members = []
    for user_id in get_member_ids(redis, room_id):
        user = users.get_by_id(redis, user_id)
        if user is not None:
            members.append(
                {
                    "id": user["id"],
                    "username": user["username"],
                    "public_key": user["public_key"],
                    "online": _is_online(redis, user_id),
                }
            )
    members.sort(key=lambda m: m["username"])
    return members


def store_wrapped_key(redis: Redis, room_id: str, target_user_id: str, wrapped_key: str) -> None:
    """Enregistre la copie de la clé de salon enveloppée pour un membre."""
    redis.hset(_keys_key(room_id), target_user_id, wrapped_key)


def list_wrapped_keys(redis: Redis, room_id: str) -> dict[str, str]:
    """Renvoie ``{target_user_id: wrapped_key}`` pour le salon."""
    return redis.hgetall(_keys_key(room_id))


def remove_wrapped_key(redis: Redis, room_id: str, user_id: str) -> None:
    """Retire la copie de la clé de salon enveloppée d'un membre (leave)."""
    redis.hdel(_keys_key(room_id), user_id)


def delete_room(redis: Redis, room_id: str) -> None:
    """Supprime complètement un salon et ses messages (dernier membre parti).

    Efface les clés Redis ``room:{id}``, ``room:{id}:members``,
    ``room:{id}:keys``, ``room:{id}:messages``, ``room:{id}:seq`` ainsi que
    chaque hash ``message:{id}`` encore référencé dans le feed du salon.
    """
    message_ids = redis.zrange(_feed_key(room_id), 0, -1)
    pipe = redis.pipeline()
    pipe.delete(_room_key(room_id))
    pipe.delete(_members_key(room_id))
    pipe.delete(_keys_key(room_id))
    pipe.delete(_feed_key(room_id))
    pipe.delete(_seq_key(room_id))
    for message_id in message_ids:
        pipe.delete(_message_key(message_id))
    pipe.execute()


def _feed_key(room_id: str) -> str:
    return f"{ROOM_PREFIX}{room_id}:messages"


def _seq_key(room_id: str) -> str:
    return f"{ROOM_PREFIX}{room_id}:seq"


def _message_key(message_id: str) -> str:
    return f"message:{message_id}"
