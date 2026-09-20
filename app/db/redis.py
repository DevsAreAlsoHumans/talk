"""Client Redis partagé de l'application.

Un client ``redis.Redis`` est thread-safe et réutilisable : la dépendance
FastAPI ``get_redis`` le fournit à chaque requête. Les tests peuvent injecter
un client fakeredis via ``app.state.redis``.
"""

from fastapi import Request
from redis import Redis

from app.config import settings


def client_from_url(url: str) -> Redis:
    """Crée un client Redis à partir d'une URL ``redis://``.

    ``decode_responses=True`` : les valeurs stockées (JSON, identifiants,
    ciphertext en base64) sont restituées en ``str``.
    """
    return Redis.from_url(url, decode_responses=True)


def get_redis(request: Request) -> Redis:
    """Dépendance FastAPI : renvoie le client Redis de l'application.

    Le client est posé sur ``app.state.redis`` par la factory ``create_app``,
    ce qui permet aux tests de le remplacer par un client fakeredis.
    """
    client: Redis | None = getattr(request.app.state, "redis", None)
    if client is None:
        client = client_from_url(settings.REDIS_URL)
    return client
