from __future__ import annotations

import base64
import re
from datetime import UTC, datetime

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

CurrentUser = dict


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
    user_id: str = Field(min_length=24, max_length=24)
    key_wraps: dict[str, str]


class MessageRequest(BaseModel):
    iv: str = Field(max_length=64)
    ciphertext: str = Field(min_length=10, max_length=200_000)


def _valid_b64(value: str) -> bool:
    if not re.fullmatch(r"[+/0-9A-Za-z]+={0,2}", value):
        return False
    try:
        base64.b64decode(value, validate=True)
        return True
    except Exception:
        return False


@router.get("/me")
async def me(user: dict = Depends(authenticated_user)) -> dict:
    return _user_summary(user)


@router.put("/me/public-key")
async def set_public_key(
    payload: PublicKeyRequest,
    user: dict = Depends(authenticated_user),
    _csrf=Depends(require_csrf),
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
    q: str = Query(min_length=1, max_length=30),
    user: dict = Depends(authenticated_user),
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
    _user: dict = Depends(authenticated_user),
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
    user: dict = Depends(authenticated_user),
    _csrf=Depends(require_csrf),
) -> dict:
    other_id = _to_obj(payload.user_id)
    if other_id == user["_id"]:
        raise HTTPException(
            status_code=422, detail="Impossible de discuter avec soi-même."
        )

    other = await mongo.db[USERS_COLLECTION].find_one({"_id": other_id})
    if other is None:
        raise HTTPException(status_code=404, detail="Utilisateur introuvable.")

    own_id_str = str(user["_id"])
    other_id_str = str(other_id)
    invalid = set(payload.key_wraps) - {own_id_str, other_id_str}
    if invalid:
        raise HTTPException(status_code=422, detail="Clés de salle invalides.")
    if len(payload.key_wraps) != 2:
        raise HTTPException(status_code=422, detail="Clés de salle invalides.")
    for value in payload.key_wraps.values():
        if not _valid_b64(value) or len(value) > 512:
            raise HTTPException(status_code=422, detail="Clé de salle invalide.")

    members = sorted([user["_id"], other_id], key=str)
    existing = await _existing_conversation(members)
    if existing is not None:
        return {"id": str(existing["_id"]), "created": False}

    conversation = {
        "members": members,
        "key_wraps": payload.key_wraps,
        "created_at": datetime.now(UTC),
        "last_message_at": None,
    }
    result = await mongo.db[CONVERSATIONS_COLLECTION].insert_one(conversation)
    return {"id": str(result.inserted_id), "created": True}


@router.get("/conversations")
async def list_conversations(user: dict = Depends(authenticated_user)) -> list[dict]:
    cursor = mongo.db[CONVERSATIONS_COLLECTION].find(
        {"members": user["_id"]}
    ).sort("last_message_at", -1)
    conversations = []
    async for conversation in cursor:
        other_id = next(
            (m for m in conversation["members"] if m != user["_id"]), None
        )
        other_name = None
        if other_id is not None:
            other = await mongo.db[USERS_COLLECTION].find_one(
                {"_id": other_id}, projection={"username": 1}
            )
            other_name = other["username"] if other else None
        conversations.append(
            {
                "id": str(conversation["_id"]),
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
    user: dict = Depends(authenticated_user),
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
    user: dict = Depends(authenticated_user),
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
    user: dict = Depends(authenticated_user),
    _csrf=Depends(require_csrf),
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