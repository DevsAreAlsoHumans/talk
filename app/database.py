import redis.asyncio as redis
from app.config import settings


def get_redis_client() -> redis.Redis:
    """Crée et retourne un client Redis asynchrone."""
    return redis.Redis(
        host=settings.REDIS_HOST,
        port=settings.REDIS_PORT,
        db=settings.REDIS_DB,
        password=settings.REDIS_PASSWORD,
        decode_responses=True,
    )


# Instance globale pour réutilisation
_redis_client: redis.Redis | None = None


async def get_redis() -> redis.Redis:
    """Dépendance FastAPI pour obtenir le client Redis."""
    global _redis_client
    if _redis_client is None:
        _redis_client = get_redis_client()
    return _redis_client


async def close_redis() -> None:
    """Ferme la connexion Redis."""
    global _redis_client
    if _redis_client:
        await _redis_client.close()
        _redis_client = None