from typing import Any

from motor.motor_asyncio import AsyncIOMotorClient, AsyncIOMotorDatabase
from pymongo import ASCENDING

from app.config import settings

client: AsyncIOMotorClient = AsyncIOMotorClient(settings.mongo_uri)
db: AsyncIOMotorDatabase = client[settings.mongo_db_name]


async def ensure_indexes() -> None:
    """Crée les index uniques requis (email, pseudo+discriminant, demandes d'ami)."""
    await db.users.create_index("email", unique=True)
    await db.users.create_index(
        [("username_lower", ASCENDING), ("discriminator", ASCENDING)], unique=True
    )
    await db.friendships.create_index(
        [("requester_id", ASCENDING), ("target_id", ASCENDING)], unique=True
    )


async def find_user_by_tag(username: str, discriminator: str) -> dict[str, Any] | None:
    """Cherche un utilisateur par pseudo (insensible à la casse) + discriminant."""
    return await db.users.find_one(
        {"username_lower": username.lower(), "discriminator": discriminator}
    )
