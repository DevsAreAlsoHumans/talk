"""Accès Redis aux messages chiffrés.

Un message est stocké sous forme de JSON dans un sorted set trié par numéro de séquence
(``{prefix}:{id}:messages``, ``room`` pour les salons, ``conv`` pour les conversations
directes entre amis). Le contenu (``ciphertext``) est déjà chiffré par le client : le
serveur n'a jamais accès au texte en clair.
"""

import json
from datetime import UTC, datetime
from uuid import uuid4

from redis.asyncio import Redis


class MessageRepository:
    def __init__(self, redis: Redis, prefix: str = "room") -> None:
        self._redis = redis
        self._prefix = prefix

    def _key(self, thread_id: str, suffix: str) -> str:
        return f"{self._prefix}:{thread_id}:{suffix}"

    async def reserve_iv(self, thread_id: str, iv: str) -> bool:
        """Anti-réutilisation de nonce : renvoie False si cet IV a déjà servi dans ce fil.

        Réutiliser un IV avec la même clé AES-GCM détruit la confidentialité ; on refuse
        donc tout message dont l'IV a déjà été vu.
        """
        return bool(await self._redis.sadd(self._key(thread_id, "ivs"), iv))

    async def append(
        self,
        *,
        thread_id: str,
        sender_id: str,
        sender_username: str,
        iv: str,
        ciphertext: str,
        kind: str = "text",
        mime: str | None = None,
    ) -> dict:
        seq = await self._redis.incr(self._key(thread_id, "seq"))
        message = {
            "id": str(uuid4()),
            "seq": seq,
            "room_id": thread_id,
            "sender_id": sender_id,
            "sender_username": sender_username,
            "kind": kind,
            "mime": mime,
            "iv": iv,
            "ciphertext": ciphertext,
            "created_at": datetime.now(UTC).isoformat(timespec="milliseconds"),
        }
        await self._redis.zadd(self._key(thread_id, "messages"), {json.dumps(message): seq})
        return message

    async def history(self, thread_id: str, *, before: int | None, limit: int) -> tuple[list[dict], bool]:
        """Renvoie `limit` messages avant `before` (ordre chronologique) et s'il en reste d'anciens."""
        max_score = f"({before}" if before is not None else "+inf"
        raw = await self._redis.zrevrangebyscore(
            self._key(thread_id, "messages"), max_score, "-inf", start=0, num=limit + 1
        )
        has_more = len(raw) > limit
        messages = [json.loads(item) for item in raw[:limit]]
        messages.reverse()
        return messages, has_more
