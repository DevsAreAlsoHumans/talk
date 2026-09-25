from datetime import datetime, timezone

from bson import ObjectId

from app.db import get_db

DEFAULT_CHANNEL_NAME = "général"


def _new_channel(name: str) -> dict:
    return {
        "_id": ObjectId(),
        "name": name,
        "created_at": datetime.now(timezone.utc),
    }


async def create_salon(name: str, owner_id: str, encrypted_salon_key: str) -> dict:
    db = get_db()
    owner = await db.users.find_one({"_id": ObjectId(owner_id)})
    salon_doc = {
        "name": name,
        "owner_id": ObjectId(owner_id),
        "members": [
            {
                "user_id": ObjectId(owner_id),
                "username": owner["username"],
                "encrypted_salon_key": encrypted_salon_key,
            }
        ],
        "channels": [_new_channel(DEFAULT_CHANNEL_NAME)],
        "key_version": 1,
        "created_at": datetime.now(timezone.utc),
    }
    result = await db.salons.insert_one(salon_doc)
    salon_doc["_id"] = result.inserted_id
    return salon_doc


async def get_user_salons(user_id: str) -> list[dict]:
    db = get_db()
    cursor = db.salons.find({"members.user_id": ObjectId(user_id)}).sort("created_at", 1)
    return await cursor.to_list(length=200)


async def get_salon(salon_id: str) -> dict | None:
    db = get_db()
    return await db.salons.find_one({"_id": ObjectId(salon_id)})


async def add_member(salon_id: str, user_id: str, encrypted_salon_key: str) -> bool:
    db = get_db()
    if not ObjectId.is_valid(user_id):
        return False
    user = await db.users.find_one({"_id": ObjectId(user_id)})
    if not user:
        return False
    result = await db.salons.update_one(
        {"_id": ObjectId(salon_id), "members.user_id": {"$ne": ObjectId(user_id)}},
        {
            "$push": {
                "members": {
                    "user_id": ObjectId(user_id),
                    "username": user["username"],
                    "encrypted_salon_key": encrypted_salon_key,
                }
            }
        },
    )
    return result.modified_count > 0


async def remove_member(salon_id: str, user_id: str, rekey: list[dict]) -> bool:
    """Retire un membre puis applique la nouvelle clé aux membres restants."""
    db = get_db()
    if not ObjectId.is_valid(user_id):
        return False
    result = await db.salons.update_one(
        {"_id": ObjectId(salon_id)},
        {"$pull": {"members": {"user_id": ObjectId(user_id)}}},
    )
    if result.modified_count == 0:
        return False

    for entry in rekey:
        if not ObjectId.is_valid(entry["user_id"]):
            continue
        await db.salons.update_one(
            {"_id": ObjectId(salon_id), "members.user_id": ObjectId(entry["user_id"])},
            {"$set": {"members.$.encrypted_salon_key": entry["encrypted_salon_key"]}},
        )
    if rekey:
        await db.salons.update_one({"_id": ObjectId(salon_id)}, {"$inc": {"key_version": 1}})
    return True


async def add_channel(salon_id: str, name: str) -> dict | None:
    db = get_db()
    salon = await db.salons.find_one({"_id": ObjectId(salon_id)})
    if not salon:
        return None
    if any(c["name"].lower() == name.lower() for c in salon.get("channels", [])):
        return None
    channel = _new_channel(name)
    await db.salons.update_one({"_id": ObjectId(salon_id)}, {"$push": {"channels": channel}})
    return channel


async def channel_exists(salon_id: str, channel_id: str) -> bool:
    db = get_db()
    if not ObjectId.is_valid(channel_id):
        return False
    salon = await db.salons.find_one(
        {"_id": ObjectId(salon_id), "channels._id": ObjectId(channel_id)},
        {"_id": 1},
    )
    return salon is not None


async def is_member(salon_id: str, user_id: str) -> bool:
    db = get_db()
    if not ObjectId.is_valid(salon_id) or not ObjectId.is_valid(user_id):
        return False
    salon = await db.salons.find_one(
        {"_id": ObjectId(salon_id), "members.user_id": ObjectId(user_id)},
        {"_id": 1},
    )
    return salon is not None
