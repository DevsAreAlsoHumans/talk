"""Rate limiting anti bruteforce, compteur Redis a fenetre glissante simplifie."""

from fastapi import HTTPException, status
from redis import Redis


def enforce_rate_limit(redis: Redis, key: str, *, limit: int, window: int) -> None:
    counter = redis.incr(key)
    if counter == 1:
        redis.expire(key, window)
    if counter > limit:
        retry_after = redis.ttl(key) or window
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Trop de tentatives, reessayez plus tard.",
            headers={"Retry-After": str(retry_after)},
        )
