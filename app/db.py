from motor.motor_asyncio import AsyncIOMotorClient, AsyncIOMotorDatabase

from app.config import Settings, settings


class Mongo:
    def __init__(self, settings: Settings) -> None:
        self._settings = settings
        self._client: AsyncIOMotorClient | None = None

    async def connect(self) -> None:
        self._client = AsyncIOMotorClient(
            self._settings.mongo_uri, serverSelectionTimeoutMS=5000
        )

    async def close(self) -> None:
        if self._client is not None:
            self._client.close()
            self._client = None

    async def ping(self) -> None:
        if self._client is None:
            raise RuntimeError("MongoDB n'est pas connectée")
        await self._client.admin.command("ping")

    @property
    def db(self) -> AsyncIOMotorDatabase:
        if self._client is None:
            raise RuntimeError("MongoDB n'est pas connectée")
        return self._client[self._settings.mongo_dbname]


mongo = Mongo(settings)