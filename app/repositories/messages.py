"""Accès Redis aux messages chiffrés.

Un message est stocké sous forme de JSON dans un sorted set trié par numéro de séquence
(``room:{id}:messages``). Le contenu (``ciphertext``) est déjà chiffré par le client :
le serveur n'a jamais accès au texte en clair.
"""

import json
from datetime import UTC, datetime
from uuid import uuid4

from redis.asyncio import Redis


class MessageRepository:
    def __init__(self, redis: Redis) -> None:
        self._redis = redis

    async def reserve_iv(self, room_id: str, iv: str) -> bool:
        """Anti-réutilisation de nonce : renvoie False si cet IV a déjà servi dans ce salon.

        Réutiliser un IV avec la même clé AES-GCM détruit la confidentialité ; on refuse
        donc tout message dont l'IV a déjà été vu.
        """
        return bool(await self._redis.sadd(f"room:{room_id}:ivs", iv))

    async def append(
        self,
        *,
        room_id: str,
        sender_id: str,
        sender_username: str,
        iv: str,
        ciphertext: str,
        kind: str = "text",
        mime: str | None = None,
    ) -> dict:
        seq = await self._redis.incr(f"room:{room_id}:seq")
        message = {
            "id": str(uuid4()),
            "seq": seq,
            "room_id": room_id,
            "sender_id": sender_id,
            "sender_username": sender_username,
            "kind": kind,
            "mime": mime,
            "iv": iv,
            "ciphertext": ciphertext,
            "created_at": datetime.now(UTC).isoformat(timespec="milliseconds"),
        }
        await self._redis.zadd(f"room:{room_id}:messages", {json.dumps(message): seq})
        return message

    async def history(self, room_id: str, *, before: int | None, limit: int) -> tuple[list[dict], bool]:
        """Renvoie `limit` messages avant `before` (ordre chronologique) et s'il en reste d'anciens."""
        max_score = f"({before}" if before is not None else "+inf"
        raw = await self._redis.zrevrangebyscore(
            f"room:{room_id}:messages", max_score, "-inf", start=0, num=limit + 1
        )
        has_more = len(raw) > limit
        messages = [json.loads(item) for item in raw[:limit]]
        messages.reverse()
        return messages, has_more
