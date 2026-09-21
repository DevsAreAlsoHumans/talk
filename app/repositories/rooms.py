"""Accès Redis aux salons, à leurs membres, aux grades et aux clés enveloppées.

Clés :
  room:{id}               hash  (nom, propriétaire, date)
  room:{id}:members       set   d'identifiants utilisateur
  room:{id}:roles         hash  utilisateur → grade (owner = chef, co = sous-chef, member)
  room:{id}:keys          hash  utilisateur → clé de salon enveloppée (JSON)
  user:{id}:rooms         set   des salons d'un utilisateur

Le serveur ne stocke que des clés de salon *chiffrées pour chaque membre* : il ne peut
jamais retrouver la clé en clair.
"""

import json
from datetime import UTC, datetime
from uuid import uuid4

from redis.asyncio import Redis

ROLE_OWNER = "owner"  # chef
ROLE_CO = "co"  # sous-chef
ROLE_MEMBER = "member"


class RoomRepository:
    def __init__(self, redis: Redis) -> None:
        self._redis = redis

    async def create(self, *, owner_id: str, name: str, wrapped_key: dict) -> dict[str, str]:
        room = {
            "id": str(uuid4()),
            "name": name,
            "owner_id": owner_id,
            "created_at": datetime.now(UTC).isoformat(timespec="milliseconds"),
        }
        room_id = room["id"]
        async with self._redis.pipeline(transaction=True) as pipe:
            pipe.hset(f"room:{room_id}", mapping=room)
            pipe.sadd(f"room:{room_id}:members", owner_id)
            pipe.hset(f"room:{room_id}:roles", owner_id, ROLE_OWNER)
            pipe.hset(f"room:{room_id}:keys", owner_id, json.dumps(wrapped_key))
            pipe.sadd(f"user:{owner_id}:rooms", room_id)
            await pipe.execute()
        return room

    async def get(self, room_id: str) -> dict[str, str] | None:
        return await self._redis.hgetall(f"room:{room_id}") or None

    async def list_for_user(self, user_id: str) -> list[dict]:
        room_ids = sorted(await self._redis.smembers(f"user:{user_id}:rooms"))
        if not room_ids:
            return []
        async with self._redis.pipeline(transaction=False) as pipe:
            for room_id in room_ids:
                pipe.hgetall(f"room:{room_id}")
                pipe.scard(f"room:{room_id}:members")
            results = await pipe.execute()
        rooms = []
        for index in range(0, len(results), 2):
            room, member_count = results[index], results[index + 1]
            if room:
                rooms.append({**room, "member_count": member_count})
        return sorted(rooms, key=lambda room: room["created_at"])

    async def is_member(self, room_id: str, user_id: str) -> bool:
        return bool(await self._redis.sismember(f"room:{room_id}:members", user_id))

    async def member_ids(self, room_id: str) -> set[str]:
        return set(await self._redis.smembers(f"room:{room_id}:members"))

    async def add_member(self, *, room_id: str, user_id: str, wrapped_key: dict) -> bool:
        """Ajoute un membre ; renvoie False s'il l'était déjà. Un nouveau venu est du grade « membre »."""
        if not await self._redis.sadd(f"room:{room_id}:members", user_id):
            return False
        async with self._redis.pipeline(transaction=True) as pipe:
            pipe.hset(f"room:{room_id}:keys", user_id, json.dumps(wrapped_key))
            pipe.hset(f"room:{room_id}:roles", user_id, ROLE_MEMBER)
            pipe.sadd(f"user:{user_id}:rooms", room_id)
            await pipe.execute()
        return True

    async def get_wrapped_key(self, room_id: str, user_id: str) -> dict | None:
        raw = await self._redis.hget(f"room:{room_id}:keys", user_id)
        return json.loads(raw) if raw else None

    async def room_ids(self, user_id: str) -> set[str]:
        return set(await self._redis.smembers(f"user:{user_id}:rooms"))

    async def has_shared_room(self, first_id: str, second_id: str) -> bool:
        """Vrai si deux utilisateurs appartiennent à au moins un salon commun.

        C'est la condition minimale pour s'envoyer un appel vocal : on ne peut appeler
        que quelqu'un dont on partage un salon (ou avec qui on est ami, voir ws.py).
        """
        return bool(await self._redis.sinter(f"user:{first_id}:rooms", f"user:{second_id}:rooms"))

    # ---------- Grades ----------

    async def get_role(self, room_id: str, user_id: str) -> str:
        return await self._redis.hget(f"room:{room_id}:roles", user_id) or ROLE_MEMBER

    async def get_roles(self, room_id: str) -> dict[str, str]:
        return dict(await self._redis.hgetall(f"room:{room_id}:roles"))

    async def set_role(self, room_id: str, user_id: str, role: str) -> None:
        await self._redis.hset(f"room:{room_id}:roles", user_id, role)

    async def set_avatar(self, room_id: str, user_id: str, envelope: dict) -> None:
        """Enregistre l'avatar chiffré (avec la clé du salon) d'un membre pour ce salon."""
        await self._redis.hset(f"room:{room_id}:avatars", user_id, json.dumps(envelope))

    async def get_avatars(self, room_id: str) -> dict[str, dict]:
        raw = await self._redis.hgetall(f"room:{room_id}:avatars")
        return {user_id: json.loads(value) for user_id, value in raw.items()}
