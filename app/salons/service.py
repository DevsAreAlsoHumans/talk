from datetime import datetime, timezone

from bson import ObjectId

from app.crypto.service import key_fingerprint
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
                "fingerprint": key_fingerprint(owner.get("public_key")),
            }
        ],
        "channels": [_new_channel(DEFAULT_CHANNEL_NAME)],
        "key_version": 1,
        "is_direct": False,
        "created_at": datetime.now(timezone.utc),
    }
    result = await db.salons.insert_one(salon_doc)
    salon_doc["_id"] = result.inserted_id
    return salon_doc


async def find_direct(user_a: str, user_b: str) -> dict | None:
    """Conversation privée existante entre deux personnes, s'il y en a une."""
    db = get_db()
    return await db.salons.find_one(
        {
            "is_direct": True,
            "members.user_id": {"$all": [ObjectId(user_a), ObjectId(user_b)]},
        }
    )


async def create_direct(
    creator: dict,
    target: dict,
    key_for_creator: str,
    key_for_target: str,
) -> dict:
    """Crée une conversation à deux.

    C'est un salon comme un autre, marqué `is_direct` : le modèle de
    chiffrement et de diffusion reste donc strictement le même.
    """
    db = get_db()
    salon_doc = {
        # Le nom affiché est calculé côté client selon qui regarde.
        "name": f"{creator['username']} ↔ {target['username']}",
        "owner_id": creator["_id"],
        "members": [
            {
                "user_id": creator["_id"],
                "username": creator["username"],
                "encrypted_salon_key": key_for_creator,
                "fingerprint": key_fingerprint(creator.get("public_key")),
            },
            {
                "user_id": target["_id"],
                "username": target["username"],
                "encrypted_salon_key": key_for_target,
                "fingerprint": key_fingerprint(target.get("public_key")),
            },
        ],
        "channels": [_new_channel(DEFAULT_CHANNEL_NAME)],
        "key_version": 1,
        "is_direct": True,
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
                    "fingerprint": key_fingerprint(user.get("public_key")),
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
