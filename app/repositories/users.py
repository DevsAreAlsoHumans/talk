"""Accès Redis aux comptes utilisateurs.

Clés : ``user:{id}`` (hash) et ``username:{nom}`` (index unique nom → id).
Les noms d'utilisateur sont validés par regex (``[a-z0-9_]``) avant d'arriver ici :
aucune entrée utilisateur ne peut donc injecter de séparateur ou de motif dans une clé.
"""

from datetime import UTC, datetime
from uuid import uuid4

from redis.asyncio import Redis


class UserRepository:
    def __init__(self, redis: Redis) -> None:
        self._redis = redis

    async def create(
        self, *, username: str, password_hash: str, public_key: str, encrypted_private_key: str
    ) -> dict[str, str] | None:
        """Crée le compte ; renvoie None si le nom est déjà pris (réservation atomique)."""
        user_id = str(uuid4())
        if not await self._redis.set(f"username:{username}", user_id, nx=True):
            return None
        user = {
            "id": user_id,
            "username": username,
            "display_name": username,
            "bio": "",
            "theme": "dark",
            "password_hash": password_hash,
            "public_key": public_key,
            "encrypted_private_key": encrypted_private_key,
            "created_at": datetime.now(UTC).isoformat(timespec="milliseconds"),
        }
        await self._redis.hset(f"user:{user_id}", mapping=user)
        return user

    async def get(self, user_id: str) -> dict[str, str] | None:
        return await self._redis.hgetall(f"user:{user_id}") or None

    async def get_by_username(self, username: str) -> dict[str, str] | None:
        user_id = await self._redis.get(f"username:{username}")
        return await self.get(user_id) if user_id else None

    async def update_profile(self, user_id: str, *, display_name: str, bio: str) -> dict[str, str]:
        """Met à jour le profil visible du compte (surnom, biographie)."""
        await self._redis.hset(f"user:{user_id}", mapping={"display_name": display_name, "bio": bio})
        return await self.get(user_id)

    async def set_theme(self, user_id: str, *, theme: str) -> dict[str, str]:
        """Mémorise la préférence d'affichage du compte (mode sombre / clair)."""
        await self._redis.hset(f"user:{user_id}", mapping={"theme": theme})
        return await self.get(user_id)
