import json
from datetime import datetime
from typing import Any

from redis.asyncio import Redis


def encode(value: dict[str, Any]) -> str:
    """Encode un objet API en JSON Redis."""
    return json.dumps(value, default=lambda item: item.value if hasattr(item, "value") else item.isoformat())


def decode(value: str | None) -> dict[str, Any] | None:
    """Decode un objet JSON Redis."""
    if value is None:
        return None
    return json.loads(value)


async def get_json(redis: Redis, key: str) -> dict[str, Any] | None:
    return decode(await redis.get(key))


async def set_json(redis: Redis, key: str, value: dict[str, Any]) -> None:
    await redis.set(key, encode(value))


async def delete_keys(redis: Redis, *keys: str) -> None:
    if keys:
        await redis.delete(*keys)


async def ensure_admin_user(redis: Redis, hash_password: Any) -> None:
    """Create the development admin account once when explicitly enabled."""
    email = "admin@talk.local"
    if await redis.exists(f"user:email:{email}"):
        return

    user_id = "user_admin"
    user = {
        "id": user_id,
        "username": "Admin",
        "email": email,
        "password_hash": hash_password("admin"),
        "created_at": datetime.utcnow().isoformat(),
        "role": "admin",
    }
    async with redis.pipeline(transaction=True) as pipeline:
        pipeline.set(f"user:email:{email}", user_id)
        pipeline.set("user:username:admin", user_id)
        pipeline.set(f"user:{user_id}", encode(user))
        await pipeline.execute()
