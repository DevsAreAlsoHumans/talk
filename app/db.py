from motor.motor_asyncio import AsyncIOMotorClient

from app.config import settings

client: AsyncIOMotorClient | None = None
db = None


async def connect_db():
    global client, db
    client = AsyncIOMotorClient(settings.mongodb_url)
    db = client[settings.mongodb_db]

    await db.users.create_index("username", unique=True)
    await db.users.create_index("email", unique=True)

    await db.salons.create_index("members.user_id")
    await db.salons.create_index("owner_id")

    # Index composé : pagination par salon/canal triée par _id.
    await db.messages.create_index([("salon_id", 1), ("_id", -1)])
    await db.messages.create_index([("salon_id", 1), ("channel_id", 1), ("_id", -1)])
    await db.messages.create_index("sender_id")

    await db.refresh_tokens.create_index("token")
    await db.refresh_tokens.create_index("expires_at", expireAfterSeconds=0)

    # Les événements d'audience expirent automatiquement au bout de 13 mois
    # (durée maximale recommandée par la CNIL).
    await db.analytics.create_index("created_at", expireAfterSeconds=13 * 30 * 24 * 3600)
    await db.analytics.create_index("event")


async def close_db():
    global client
    if client:
        client.close()


def get_db():
    return db
