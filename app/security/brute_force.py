from app.db.redis_client import redis_client

_MAX_ATTEMPTS = 3
_ATTEMPTS_TTL_SECONDS = 15 * 60
_LOCK_TTL_SECONDS = 15 * 60


def _attempts_key(user_id: str) -> str:
    return f"login_attempts:{user_id}"


def _lock_key(user_id: str) -> str:
    return f"login_locked:{user_id}"


async def is_locked(user_id: str) -> bool:
    """Le compte est-il temporairement verrouillé après trop d'échecs ?"""
    return await redis_client.exists(_lock_key(user_id)) == 1


async def record_failed_attempt(user_id: str) -> bool:
    """Incrémente le compteur d'échecs ; renvoie True si le compte vient d'être verrouillé."""
    key = _attempts_key(user_id)
    attempts = await redis_client.incr(key)
    if attempts == 1:
        await redis_client.expire(key, _ATTEMPTS_TTL_SECONDS)

    if attempts >= _MAX_ATTEMPTS:
        await redis_client.set(_lock_key(user_id), "1", ex=_LOCK_TTL_SECONDS)
        await redis_client.delete(key)
        return True
    return False


async def reset_attempts(user_id: str) -> None:
    """Réinitialise le compteur d'échecs après une connexion réussie."""
    await redis_client.delete(_attempts_key(user_id))
