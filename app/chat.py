from __future__ import annotations

import base64
import re
from datetime import UTC, datetime
from typing import Annotated

from bson import ObjectId
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

from app.auth import authenticated_user
from app.db import mongo
from app.security import require_csrf

router = APIRouter(prefix="/api", tags=["chat"])

USERS_COLLECTION = "Users"
CONVERSATIONS_COLLECTION = "Conversations"
MESSAGES_COLLECTION = "Messages"

CurrentUser = Annotated[dict, Depends(authenticated_user)]
Csrf = Annotated[None, Depends(require_csrf)]


def _to_obj(value: str) -> ObjectId:
    if not ObjectId.is_valid(value):
        raise HTTPException(status_code=404, detail="Ressource introuvable.")
    return ObjectId(value)


def _user_summary(user: dict) -> dict:
    return {
        "id": str(user["_id"]),
        "username": user["username"],
        "email": user.get("email"),
        "has_public_key": bool(user.get("public_key")),
    }


class PublicKeyRequest(BaseModel):
    public_key: dict = Field(max_length=4096)


class ConversationRequest(BaseModel):
    user_id: str | None = Field(default=None, min_length=24, max_length=24)
    member_ids: list[str] | None = Field(default=None, min_length=2, max_length=50)
    name: str | None = Field(default=None, min_length=1, max_length=60)
    key_wraps: dict[str, str]


class RenameRequest(BaseModel):
    name: str = Field(min_length=1, max_length=60)


class MessageRequest(BaseModel):
    iv: str = Field(max_length=64)
    ciphertext: str = Field(min_length=10, max_length=200_000)


def _valid_b64(value: str) -> bool:
    if not re.fullmatch(r"[+/0-9A-Za-z]+={0,2}", value):
        return False
    try:
        base64.b64decode(value, validate=True)
        return True
    except ValueError:
        return False


@router.get("/me")
async def me(user: CurrentUser) -> dict:
    return _user_summary(user)


@router.put("/me/public-key")
async def set_public_key(
    payload: PublicKeyRequest,
    user: CurrentUser,
    _csrf: Csrf,
) -> dict:
    key = payload.public_key
    if key.get("kty") != "RSA" or not key.get("n") or not key.get("e"):
        raise HTTPException(status_code=422, detail="Clé publique invalide.")
    await mongo.db[USERS_COLLECTION].update_one(
        {"_id": user["_id"]}, {"$set": {"public_key": key}}
    )
    return {"ok": True}


@router.get("/users/search")
async def search_users(
    q: Annotated[str, Query(min_length=1, max_length=30)],
    user: CurrentUser,
) -> list[dict]:
    pattern = re.escape(q)
    cursor = mongo.db[USERS_COLLECTION].find(
        {"username": {"$regex": pattern, "$options": "i"}, "_id": {"$ne": user["_id"]}},
        projection={"username": 1, "email": 1, "public_key": 1},
    ).limit(10)
    results = []
    async for doc in cursor:
        results.append(_user_summary(doc))
    return results


@router.get("/users/{user_id}/public-key")
async def get_public_key(
    user_id: str,
    _user: CurrentUser,
) -> dict:
    target = _to_obj(user_id)
    doc = await mongo.db[USERS_COLLECTION].find_one(
        {"_id": target}, projection={"public_key": 1}
    )
    if doc is None or not doc.get("public_key"):
        raise HTTPException(
            status_code=404, detail="L'utilisateur n'a pas encore de clé publique."
        )
    return {"user_id": user_id, "public_key": doc["public_key"]}


async def _existing_conversation(members: list[ObjectId]) -> dict | None:
    return await mongo.db[CONVERSATIONS_COLLECTION].find_one(
        {"members": {"$size": 2, "$all": members}}
    )


@router.post("/conversations", status_code=201)
async def create_conversation(
    payload: ConversationRequest,
    user: CurrentUser,
    _csrf: Csrf,
) -> dict:
    if payload.user_id is not None and payload.member_ids is not None:
        raise HTTPException(
            status_code=422, detail="Demande de création invalide."
        )

    is_group = payload.member_ids is not None

    if is_group:
        other_ids = [_to_obj(uid) for uid in payload.member_ids]
        if len({str(oid) for oid in other_ids}) != len(other_ids):
            raise HTTPException(
                status_code=422, detail="Membres en double."
            )
        if any(oid == user["_id"] for oid in other_ids):
            raise HTTPException(
                status_code=422, detail="Impossible de s'ajouter soi-même."
            )
        for oid in other_ids:
            target = await mongo.db[USERS_COLLECTION].find_one(
                {"_id": oid}, projection={"_id": 1}
            )
            if target is None:
                raise HTTPException(
                    status_code=404, detail="Utilisateur introuvable."
                )
        all_members = {user["_id"], *other_ids}
    else:
        other_id = _to_obj(payload.user_id)
        if other_id == user["_id"]:
            raise HTTPException(
                status_code=422, detail="Impossible de discuter avec soi-même."
            )
        other = await mongo.db[USERS_COLLECTION].find_one({"_id": other_id})
        if other is None:
            raise HTTPException(status_code=404, detail="Utilisateur introuvable.")
        all_members = {user["_id"], other_id}

    member_strs = {str(m) for m in all_members}
    if set(payload.key_wraps) != member_strs:
        raise HTTPException(status_code=422, detail="Clés de salle invalides.")
    for value in payload.key_wraps.values():
        if not _valid_b64(value) or len(value) > 512:
            raise HTTPException(status_code=422, detail="Clé de salle invalide.")

    members = sorted(all_members, key=str)
    if not is_group:
        existing = await _existing_conversation(members)
        if existing is not None:
            return {"id": str(existing["_id"]), "created": False}

    conversation = {
        "type": "group" if is_group else "direct",
        "members": members,
        "key_wraps": payload.key_wraps,
        "created_at": datetime.now(UTC),
        "last_message_at": None,
    }
    if is_group:
        conversation["name"] = (
            (payload.name or "").strip() or "Conversation de groupe"
        )
    result = await mongo.db[CONVERSATIONS_COLLECTION].insert_one(conversation)
    return {"id": str(result.inserted_id), "created": True}


@router.get("/conversations")
async def list_conversations(user: CurrentUser) -> list[dict]:
    cursor = mongo.db[CONVERSATIONS_COLLECTION].find(
        {"members": user["_id"]}
    ).sort("last_message_at", -1)
    conversations = []
    async for conversation in cursor:
        is_group = conversation.get("type") == "group"
        other_ids = [
            m for m in conversation["members"] if m != user["_id"]
        ]
        members = []
        for oid in other_ids:
            other = await mongo.db[USERS_COLLECTION].find_one(
                {"_id": oid}, projection={"username": 1}
            )
            members.append(
                {
                    "id": str(oid),
                    "username": other["username"] if other else "inconnu",
                }
            )
        other_id = other_ids[0] if other_ids else None
        other_name = next(
            (m["username"] for m in members if m["id"] == str(other_id)), None
        )
        conversations.append(
            {
                "id": str(conversation["_id"]),
                "type": "group" if is_group else "direct",
                "name": conversation.get("name"),
                "members": members,
                "member_count": len(conversation["members"]),
                "created_at": conversation["created_at"],
                "last_message_at": conversation.get("last_message_at"),
                "other_user": (
                    {"id": str(other_id), "username": other_name}
                    if other_id is not None
                    else None
                ),
                "has_keys": str(user["_id"]) in conversation.get("key_wraps", {}),
            }
        )
    return conversations


async def _get_conversation_for_user(
    conversation_id: ObjectId, user: dict
) -> dict:
    conversation = await mongo.db[CONVERSATIONS_COLLECTION].find_one(
        {"_id": conversation_id, "members": user["_id"]}
    )
    if conversation is None:
        raise HTTPException(status_code=404, detail="Conversation introuvable.")
    return conversation


@router.get("/conversations/{conversation_id}/keys")
async def get_conversation_keys(
    conversation_id: str,
    user: CurrentUser,
) -> dict:
    conversation = await _get_conversation_for_user(
        _to_obj(conversation_id), user
    )
    wrapped = conversation.get("key_wraps", {}).get(str(user["_id"]))
    if not wrapped:
        raise HTTPException(status_code=404, detail="Clé de salle introuvable.")
    return {"wrapped": wrapped}


@router.get("/conversations/{conversation_id}/messages")
async def list_messages(
    conversation_id: str,
    user: CurrentUser,
) -> list[dict]:
    conversation = await _get_conversation_for_user(
        _to_obj(conversation_id), user
    )
    cursor = mongo.db[MESSAGES_COLLECTION].find(
        {"conversation_id": conversation["_id"]}
    ).sort("created_at", 1)
    messages = []
    async for message in cursor:
        sender = await mongo.db[USERS_COLLECTION].find_one(
            {"_id": message["sender_id"]}, projection={"username": 1}
        )
        messages.append(
            {
                "id": str(message["_id"]),
                "sender_id": str(message["sender_id"]),
                "sender_username": sender["username"] if sender else "inconnu",
                "iv": message["iv"],
                "ciphertext": message["ciphertext"],
                "created_at": message["created_at"],
            }
        )
    return messages


@router.post("/conversations/{conversation_id}/messages", status_code=201)
async def send_message(
    conversation_id: str,
    payload: MessageRequest,
    user: CurrentUser,
    _csrf: Csrf,
) -> dict:
    if not _valid_b64(payload.iv) or len(payload.iv) > 32:
        raise HTTPException(status_code=422, detail="IV invalide.")
    if not _valid_b64(payload.ciphertext):
        raise HTTPException(status_code=422, detail="Message invalide.")

    conversation = await _get_conversation_for_user(
        _to_obj(conversation_id), user
    )
    now = datetime.now(UTC)
    message = {
        "conversation_id": conversation["_id"],
        "sender_id": user["_id"],
        "iv": payload.iv,
        "ciphertext": payload.ciphertext,
        "created_at": now,
    }
    result = await mongo.db[MESSAGES_COLLECTION].insert_one(message)
    await mongo.db[CONVERSATIONS_COLLECTION].update_one(
        {"_id": conversation["_id"]},
        {"$set": {"last_message_at": now}},
    )
    return {"id": str(result.inserted_id)}


async def _delete_conversation(conversation_id: ObjectId) -> None:
    await mongo.db[CONVERSATIONS_COLLECTION].delete_one({"_id": conversation_id})
    await mongo.db[MESSAGES_COLLECTION].delete_many(
        {"conversation_id": conversation_id}
    )


@router.patch("/conversations/{conversation_id}")
async def rename_conversation(
    conversation_id: str,
    payload: RenameRequest,
    user: CurrentUser,
    _csrf: Csrf,
) -> dict:
    conversation = await _get_conversation_for_user(
        _to_obj(conversation_id), user
    )
    if conversation.get("type") != "group":
        raise HTTPException(
            status_code=422,
            detail="Seules les conversations de groupe sont renommables.",
        )
    name = payload.name.strip()
    if not name:
        raise HTTPException(status_code=422, detail="Nom invalide.")
    await mongo.db[CONVERSATIONS_COLLECTION].update_one(
        {"_id": conversation["_id"]}, {"$set": {"name": name}}
    )
    return {"ok": True, "name": name}


@router.post("/conversations/{conversation_id}/members/{user_id}/remove")
async def remove_member(
    conversation_id: str,
    user_id: str,
    user: CurrentUser,
    _csrf: Csrf,
) -> dict:
    conversation = await _get_conversation_for_user(
        _to_obj(conversation_id), user
    )
    target = _to_obj(user_id)
    if target == user["_id"]:
        raise HTTPException(
            status_code=422, detail="Utilisez le bouton quitter."
        )
    if target not in conversation["members"]:
        raise HTTPException(
            status_code=404, detail="Cet utilisateur n'est pas dans la conversation."
        )
    await mongo.db[CONVERSATIONS_COLLECTION].update_one(
        {"_id": conversation["_id"]},
        {
            "$pull": {"members": target},
            "$unset": {f"key_wraps.{target!s}": ""},
        },
    )
    if len(conversation["members"]) - 1 < 2:
        await _delete_conversation(conversation["_id"])
        return {"deleted": True}
    return {"deleted": False, "member_count": len(conversation["members"]) - 1}


@router.post("/conversations/{conversation_id}/leave")
async def leave_conversation(
    conversation_id: str,
    user: CurrentUser,
    _csrf: Csrf,
) -> dict:
    conversation = await _get_conversation_for_user(
        _to_obj(conversation_id), user
    )
    if len(conversation["members"]) <= 2:
        await _delete_conversation(conversation["_id"])
        return {"deleted": True}
    await mongo.db[CONVERSATIONS_COLLECTION].update_one(
        {"_id": conversation["_id"]},
        {
            "$pull": {"members": user["_id"]},
            "$unset": {f"key_wraps.{user['_id']!s}": ""},
        },
    )
    return {"deleted": False, "member_count": len(conversation["members"]) - 1}