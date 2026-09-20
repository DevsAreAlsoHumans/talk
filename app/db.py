"""Couche d'accès données.

E2EE : la BDD ne stocke QUE des blobs opaques (ciphertext, hash Argon2) —
jamais de texte clair ni de clés privées utilisateur.
"""

from datetime import UTC, datetime
from typing import Any

from motor.motor_asyncio import AsyncIOMotorClient, AsyncIOMotorDatabase
from pymongo import ReturnDocument
from pymongo.errors import DuplicateKeyError

from .config import get_settings


def utcnow() -> datetime:
    """Datetime UTC — les dates « naïves » posent des pièges de TZ en prod."""
    return datetime.now(UTC)


class Database:
    """Interface commune (implémentation réelle = Mongo, test = InMemory)."""

    async def get_user_by_username(self, username: str) -> dict[str, Any] | None: ...

    async def create_user(self, username: str, password_hash: str) -> dict[str, Any] | None: ...

    async def get_user_by_id(self, user_id: str) -> dict[str, Any] | None: ...

    async def create_room(self, name: str, owner_id: str) -> dict[str, Any]: ...

    async def get_room_by_id(self, room_id: str) -> dict[str, Any] | None: ...

    async def list_rooms_for_user(self, username: str) -> list[dict[str, Any]]: ...

    async def add_room_member(self, room_id: str, username: str) -> bool: ...

    async def set_public_key(self, username: str, public_key: str) -> None: ...

    async def get_public_key(self, username: str) -> str | None: ...

    async def set_wrapped_key(self, room_id: str, username: str, blob: dict[str, Any]) -> None: ...

    async def get_wrapped_key(self, room_id: str, username: str) -> dict[str, Any] | None: ...

    async def create_channel(self, room_id: str, name: str) -> dict[str, Any] | None: ...

    async def list_channels(self, room_id: str) -> list[dict[str, Any]]: ...

    async def get_channel(self, room_id: str, channel_id: str) -> dict[str, Any] | None: ...

    async def delete_channel(self, room_id: str, channel_id: str) -> bool: ...

    async def add_channel_message(
        self, room_id: str, channel_id: str, sender: str, blob: str
    ) -> dict[str, Any] | None: ...

    async def get_channel_messages(
        self, room_id: str, channel_id: str, after: int | None = None, limit: int = 200
    ) -> list[dict[str, Any]]: ...

    async def close(self) -> None: ...


class Mongo(Database):
    def __init__(self, uri: str, db_name: str) -> None:
        self._client: AsyncIOMotorClient[Any] = AsyncIOMotorClient(uri)
        self._db: AsyncIOMotorDatabase[Any] = self._client[db_name]

    async def init_indexes(self) -> None:
        # Index unique sur username : verrou anti-race pour le double enregistrement
        await self._db.users.create_index("username", unique=True)
        # Une clé publique par utilisateur
        await self._db.keys.create_index("username", unique=True)
        # Une clé enveloppée par (salon, membre)
        await self._db.wrapped_keys.create_index(
            [("room_id", 1), ("username", 1)], unique=True
        )
        # Un canal par nom au sein d'un même salon (anti-doublon)
        await self._db.channels.create_index(
            [("room_id", 1), ("name", 1)], unique=True
        )

    async def get_user_by_username(self, username: str) -> dict[str, Any] | None:
        return await self._db.users.find_one({"username": username})

    async def create_user(self, username: str, password_hash: str) -> dict[str, Any] | None:
        doc = {
            "username": username,
            "password_hash": password_hash,  # Argon2id, jamais le mot de passe
            "created_at": utcnow(),
            "role": "user",
        }
        try:
            await self._db.users.insert_one(doc)
        except DuplicateKeyError:
            return None
        return await self.get_user_by_username(username)

    async def get_user_by_id(self, user_id: str) -> dict[str, Any] | None:
        from bson import ObjectId

        if not ObjectId.is_valid(user_id):
            return None
        return await self._db.users.find_one({"_id": ObjectId(user_id)})

    async def create_room(self, name: str, owner_id: str) -> dict[str, Any]:
        room = {
            "name": name,
            "owner_id": owner_id,
            "members": [owner_id],
            "created_at": utcnow(),
        }
        res = await self._db.rooms.insert_one(room)
        room_id = res.inserted_id
        # Modèle Discord : un salon naît avec un premier canal `general`.
        await self._db.channels.insert_one(
            {
                "room_id": room_id,
                "name": "general",
                "created_at": utcnow(),
                "message_blobs": [],
                "msg_seq": 0,
            }
        )
        return await self._db.rooms.find_one({"_id": room_id})

    async def get_room_by_id(self, room_id: str) -> dict[str, Any] | None:
        from bson import ObjectId

        if not ObjectId.is_valid(room_id):
            return None
        return await self._db.rooms.find_one({"_id": ObjectId(room_id)})

    async def list_rooms_for_user(self, username: str) -> list[dict[str, Any]]:
        cursor = self._db.rooms.find({"members": username}).sort("created_at", -1)
        return await cursor.to_list(length=100)

    async def add_room_member(self, room_id: str, username: str) -> bool:
        from bson import ObjectId

        if not ObjectId.is_valid(room_id):
            return False
        res = await self._db.rooms.update_one(
            {"_id": ObjectId(room_id)}, {"$addToSet": {"members": username}}
        )
        return res.modified_count > 0

    async def set_public_key(self, username: str, public_key: str) -> None:
        await self._db.keys.update_one(
            {"username": username}, {"$set": {"public_key": public_key}}, upsert=True
        )

    async def get_public_key(self, username: str) -> str | None:
        doc = await self._db.keys.find_one({"username": username})
        return doc["public_key"] if doc else None

    async def set_wrapped_key(self, room_id: str, username: str, blob: dict[str, Any]) -> None:
        await self._db.wrapped_keys.update_one(
            {"room_id": room_id, "username": username}, {"$set": {"blob": blob}}, upsert=True
        )

    async def get_wrapped_key(self, room_id: str, username: str) -> dict[str, Any] | None:
        doc = await self._db.wrapped_keys.find_one(
            {"room_id": room_id, "username": username}
        )
        return doc["blob"] if doc else None

    async def add_channel_message(
        self, room_id: str, channel_id: str, sender: str, blob: str
    ) -> dict[str, Any] | None:
        from bson import ObjectId

        if not ObjectId.is_valid(room_id) or not ObjectId.is_valid(channel_id):
            return None
        channel = await self._db.channels.find_one_and_update(
            {"_id": ObjectId(channel_id), "room_id": ObjectId(room_id)},
            {"$inc": {"msg_seq": 1}},
            return_document=ReturnDocument.AFTER,
        )
        if channel is None:
            return None
        doc = {"n": channel["msg_seq"], "sender": sender, "ts": utcnow(), "payload": blob}
        await self._db.channels.update_one(
            {"_id": ObjectId(channel_id)}, {"$push": {"message_blobs": doc}}
        )
        return doc

    async def get_channel_messages(
        self, room_id: str, channel_id: str, after: int | None = None, limit: int = 200
    ) -> list[dict[str, Any]]:
        from bson import ObjectId

        if not ObjectId.is_valid(room_id) or not ObjectId.is_valid(channel_id):
            return []
        channel = await self._db.channels.find_one(
            {"_id": ObjectId(channel_id), "room_id": ObjectId(room_id)},
            {"message_blobs": 1},
        )
        if channel is None:
            return []
        msgs = channel.get("message_blobs") or []
        msgs = [m for m in msgs if after is None or m["n"] > after]
        msgs.sort(key=lambda m: m["n"])
        return msgs[-limit:]

    async def create_channel(self, room_id: str, name: str) -> dict[str, Any] | None:
        from bson import ObjectId

        if not ObjectId.is_valid(room_id):
            return None
        doc = {
            "room_id": ObjectId(room_id),
            "name": name,
            "created_at": utcnow(),
            # Les messages sont des blobs chiffrés {sender, n, ts, payload} :
            # indéchiffrables côté serveur par construction.
            "message_blobs": [],
            "msg_seq": 0,
        }
        try:
            res = await self._db.channels.insert_one(doc)
        except DuplicateKeyError:
            return None
        return await self._db.channels.find_one({"_id": res.inserted_id})

    async def list_channels(self, room_id: str) -> list[dict[str, Any]]:
        from bson import ObjectId

        if not ObjectId.is_valid(room_id):
            return []
        cursor = self._db.channels.find({"room_id": ObjectId(room_id)}).sort(
            "created_at", 1
        )
        return await cursor.to_list(length=100)

    async def get_channel(self, room_id: str, channel_id: str) -> dict[str, Any] | None:
        from bson import ObjectId

        if not ObjectId.is_valid(room_id) or not ObjectId.is_valid(channel_id):
            return None
        return await self._db.channels.find_one(
            {"_id": ObjectId(channel_id), "room_id": ObjectId(room_id)}
        )

    async def delete_channel(self, room_id: str, channel_id: str) -> bool:
        from bson import ObjectId

        if not ObjectId.is_valid(room_id) or not ObjectId.is_valid(channel_id):
            return False
        res = await self._db.channels.delete_one(
            {"_id": ObjectId(channel_id), "room_id": ObjectId(room_id)}
        )
        return res.deleted_count > 0

    async def close(self) -> None:
        self._client.close()


# Singleton : créé au premier accès (connexion lazy du driver motor).
_db: Database | None = None


async def get_db() -> Database:
    """Dependency FastAPI — les tests surchargent cette fonction."""
    global _db
    if _db is None:
        settings = get_settings()
        mongo = Mongo(settings.mongodb_uri, settings.db_name)
        await mongo.init_indexes()
        _db = mongo
    return _db


async def close_db() -> None:
    global _db
    if _db is not None:
        await _db.close()
        _db = None
