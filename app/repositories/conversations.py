"""Accès Redis aux conversations directes entre deux amis.

Une conversation est un fil de discussion à *exactement deux* participants (les deux
amis), chiffré avec une clé AES-256 dédiée, enveloppée pour chacun des deux : même
modèle de clés que les salons, sans propriétaire ni ajout de membre possible.

Clés :
  conv:{id}                 hash  (date de création, initiateur)
  conv:{id}:members         set   les deux identifiants utilisateur
  conv:{id}:keys            hash  utilisateur → clé de conversation *enveloppée* (JSON)
  conv:pair:{a}:{b}         string id de la conversation (index d'unicité par paire)
  user:{id}:convs           set   conversations d'un utilisateur
  conv:{id}:messages · seq · ivs  (gérés par MessageRepository, préfixe ``conv``)
"""

import json
from datetime import UTC, datetime
from uuid import uuid4

from redis.asyncio import Redis


class ConversationRepository:
    def __init__(self, redis: Redis) -> None:
        self._redis = redis

    def _keys(self, conv_id: str) -> str:
        return f"conv:{conv_id}:keys"

    def _members(self, conv_id: str) -> str:
        return f"conv:{conv_id}:members"

    def _pair_key(self, first_id: str, second_id: str) -> str:
        return f"conv:pair:{min(first_id, second_id)}:{max(first_id, second_id)}"

    async def create(
        self,
        *,
        initiator_id: str,
        peer_id: str,
        wrapped_key_initiator: dict,
        wrapped_key_peer: dict,
    ) -> tuple[dict[str, str] | None, bool]:
        """Crée la conversation ; renvoie (conversation, True) ou (existante, False)."""
        pair_key = self._pair_key(initiator_id, peer_id)
        existing = await self._redis.get(pair_key)
        if existing:
            return await self.get(existing), False
        conv = {
            "id": str(uuid4()),
            "initiator_id": initiator_id,
            "created_at": datetime.now(UTC).isoformat(timespec="milliseconds"),
        }
        conv_id = conv["id"]
        async with self._redis.pipeline(transaction=True) as pipe:
            pipe.hset(f"conv:{conv_id}", mapping=conv)
            pipe.sadd(self._members(conv_id), initiator_id, peer_id)
            pipe.hset(
                self._keys(conv_id),
                mapping={
                    initiator_id: json.dumps(wrapped_key_initiator),
                    peer_id: json.dumps(wrapped_key_peer),
                },
            )
            pipe.sadd(f"user:{initiator_id}:convs", conv_id)
            pipe.sadd(f"user:{peer_id}:convs", conv_id)
            pipe.set(pair_key, conv_id)
            await pipe.execute()
        return conv, True

    async def get(self, conv_id: str) -> dict[str, str] | None:
        return await self._redis.hgetall(f"conv:{conv_id}") or None

    async def is_member(self, conv_id: str, user_id: str) -> bool:
        return bool(await self._redis.sismember(self._members(conv_id), user_id))

    async def member_ids(self, conv_id: str) -> set[str]:
        return set(await self._redis.smembers(self._members(conv_id)))

    async def peer_id(self, conv_id: str, user_id: str) -> str | None:
        others = await self.member_ids(conv_id)
        others.discard(user_id)
        return next(iter(others), None)

    async def conv_ids(self, user_id: str) -> set[str]:
        return set(await self._redis.smembers(f"user:{user_id}:convs"))

    async def get_wrapped_key(self, conv_id: str, user_id: str) -> dict | None:
        raw = await self._redis.hget(self._keys(conv_id), user_id)
        return json.loads(raw) if raw else None
