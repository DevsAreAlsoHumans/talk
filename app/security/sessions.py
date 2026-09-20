"""Sessions serveur stockées dans Redis.

Le cookie ne contient qu'un identifiant aléatoire opaque (256 bits). Redis ne stocke que
son empreinte SHA-256 : une fuite de la base ne fournit donc aucun cookie valide.
"""

import hashlib
import secrets

from redis.asyncio import Redis

MAX_SESSION_ID_LENGTH = 128


def hash_session_id(session_id: str) -> str:
    return hashlib.sha256(session_id.encode()).hexdigest()


class SessionStore:
    def __init__(self, redis: Redis, ttl_seconds: int) -> None:
        self._redis = redis
        self._ttl = ttl_seconds

    @staticmethod
    def _key(session_id: str) -> str:
        return f"session:{hash_session_id(session_id)}"

    async def create(self, user_id: str) -> str:
        session_id = secrets.token_urlsafe(32)
        await self._redis.set(self._key(session_id), user_id, ex=self._ttl)
        return session_id

    async def get_user_id(self, session_id: str | None) -> str | None:
        if not session_id or len(session_id) > MAX_SESSION_ID_LENGTH:
            return None
        return await self._redis.get(self._key(session_id))

    async def destroy(self, session_id: str | None) -> None:
        if session_id and len(session_id) <= MAX_SESSION_ID_LENGTH:
            await self._redis.delete(self._key(session_id))
