"""Limitation de débit à fenêtre fixe, basée sur Redis."""

from redis.asyncio import Redis


async def is_rate_limited(redis: Redis, key: str, limit: int, window_seconds: int) -> bool:
    """Compte une tentative pour `key` ; renvoie True si `limit` est dépassée dans la fenêtre.

    `SET ... NX EX` puis `INCR` dans une transaction : la clé a toujours un TTL,
    donc un blocage ne peut jamais devenir permanent.
    """
    async with redis.pipeline(transaction=True) as pipe:
        pipe.set(key, 0, ex=window_seconds, nx=True)
        pipe.incr(key)
        _, attempts = await pipe.execute()
    return attempts > limit


async def reset(redis: Redis, key: str) -> None:
    await redis.delete(key)
