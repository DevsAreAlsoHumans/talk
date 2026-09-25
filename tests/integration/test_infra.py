from app.db.mongo import client as mongo_client
from app.db.redis_client import redis_client


async def test_mongo_connection() -> None:
    """Vérifie que MongoDB (docker-compose ou CI) répond à un ping."""
    result = await mongo_client.admin.command("ping")

    assert result["ok"] == 1


async def test_redis_connection() -> None:
    """Vérifie que Redis (docker-compose ou CI) répond à un ping."""
    assert await redis_client.ping() is True
