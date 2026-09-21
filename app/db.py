from motor.motor_asyncio import AsyncIOMotorClient

from app.config import settings

client: AsyncIOMotorClient = None
db = None


async def connect_db():
    global client, db
    client = AsyncIOMotorClient(settings.mongodb_url)
    db = client[settings.mongodb_db]
    await db.users.create_index("username", unique=True)
    await db.users.create_index("email", unique=True)
    await db.messages.create_index("salon_id")
    await db.messages.create_index("created_at")
    await db.refresh_tokens.create_index("expires_at", expireAfterSeconds=0)


async def close_db():
    global client
    if client:
        client.close()


def get_db():
    return db
