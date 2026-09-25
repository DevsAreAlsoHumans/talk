import redis.asyncio as redis

from app.config import settings

redis_client = redis.from_url(settings.redis_uri, decode_responses=True)
