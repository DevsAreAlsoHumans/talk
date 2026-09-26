from motor.motor_asyncio import AsyncIOMotorClient, AsyncIOMotorDatabase
from pymongo import ASCENDING

from app.config import settings

client: AsyncIOMotorClient = AsyncIOMotorClient(settings.mongo_uri)
db: AsyncIOMotorDatabase = client[settings.mongo_db_name]


async def ensure_indexes() -> None:
    """Crée les index uniques requis (email, pseudo+discriminant)."""
    await db.users.create_index("email", unique=True)
    await db.users.create_index(
        [("username_lower", ASCENDING), ("discriminator", ASCENDING)], unique=True
    )
