from typing import Any

from bson import ObjectId
from motor.motor_asyncio import AsyncIOMotorClient, AsyncIOMotorDatabase
from pymongo import ASCENDING, DESCENDING

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
    await db.notifications.create_index([("user_id", ASCENDING), ("created_at", DESCENDING)])
    await db.room_keys.create_index(
        [("room_id", ASCENDING), ("epoch", ASCENDING), ("member_id", ASCENDING)], unique=True
    )
    await db.rooms.create_index(
        "is_general", unique=True, partialFilterExpression={"is_general": True}
    )


async def find_user_by_tag(username: str, discriminator: str) -> dict[str, Any] | None:
    """Cherche un utilisateur par pseudo (insensible à la casse) + discriminant."""
    return await db.users.find_one(
        {"username_lower": username.lower(), "discriminator": discriminator}
    )


async def get_user_label(user_id: str) -> str:
    """Libellé pseudo#discriminant d'un utilisateur, pour des messages lisibles."""
    user = await db.users.find_one({"_id": ObjectId(user_id)})
    if user is None:
        return "un utilisateur"
    return f"{user['username']}#{user['discriminator']}"
