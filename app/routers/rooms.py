from datetime import UTC, datetime
from typing import Any

from bson import ObjectId
from bson.errors import InvalidId
from fastapi import APIRouter, Depends, HTTPException, status

from app.db.mongo import db, find_user_by_tag
from app.db.redis_client import redis_client
from app.models.room import MessageCreate, MessagePublic, RoomCreate, RoomPublic
from app.models.user import PeerPublic
from app.security.sessions import get_current_user_id, require_csrf
from app.services.realtime import room_channel

router = APIRouter(prefix="/rooms", tags=["rooms"])


def _to_room_public(room: dict[str, Any], peer_document: dict[str, Any]) -> RoomPublic:
    return RoomPublic(
        id=str(room["_id"]), type=room["type"], peer=PeerPublic.from_document(peer_document)
    )


def _to_message_public(document: dict[str, Any]) -> MessagePublic:
    return MessagePublic(
        id=str(document["_id"]),
        room_id=document["room_id"],
        sender_id=document["sender_id"],
        ciphertext=document["ciphertext"],
        iv=document["iv"],
        created_at=document["created_at"],
    )


async def _find_peer(username: str, discriminator: str) -> dict[str, Any]:
    peer = await find_user_by_tag(username, discriminator)
    if peer is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Utilisateur introuvable."
        )
    return peer


async def _get_membership_or_404(room_id: str, user_id: str) -> dict[str, Any]:
    try:
        object_id = ObjectId(room_id)
    except InvalidId as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Salon introuvable."
        ) from exc

    room = await db.rooms.find_one({"_id": object_id})
    if room is None or user_id not in room["member_ids"]:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Salon introuvable.")
    return room


@router.post("/dm", response_model=RoomPublic)
async def create_or_get_dm(
    payload: RoomCreate, user_id: str = Depends(get_current_user_id)
) -> RoomPublic:
    """Crée un salon DM avec un pseudo#discriminant, ou renvoie celui qui existe déjà."""
    peer = await _find_peer(payload.username, payload.discriminator)
    peer_id = str(peer["_id"])
    if peer_id == user_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Impossible de créer un DM avec soi-même.",
        )

    member_ids = sorted([user_id, peer_id])
    room = await db.rooms.find_one({"type": "dm", "member_ids": member_ids})
    if room is None:
        room_doc: dict[str, Any] = {
            "type": "dm",
            "members": [
                {"user_id": user_id, "role": "member"},
                {"user_id": peer_id, "role": "member"},
            ],
            "member_ids": member_ids,
            "created_at": datetime.now(UTC),
        }
        result = await db.rooms.insert_one(room_doc)
        room_doc["_id"] = result.inserted_id
        room = room_doc

    return _to_room_public(room, peer)


@router.get("", response_model=list[RoomPublic])
async def list_rooms(user_id: str = Depends(get_current_user_id)) -> list[RoomPublic]:
    """Liste les salons DM de l'utilisateur courant."""
    rooms = await db.rooms.find({"member_ids": user_id}).to_list(length=None)
    if not rooms:
        return []

    peer_ids = [
        ObjectId(next(m for m in room["member_ids"] if m != user_id)) for room in rooms
    ]
    peers = await db.users.find({"_id": {"$in": peer_ids}}).to_list(length=None)
    peers_by_id = {str(peer["_id"]): peer for peer in peers}

    result = []
    for room in rooms:
        peer_id = next(m for m in room["member_ids"] if m != user_id)
        peer_document = peers_by_id.get(peer_id)
        if peer_document is not None:
            result.append(_to_room_public(room, peer_document))
    return result


@router.get("/{room_id}/messages", response_model=list[MessagePublic])
async def list_messages(
    room_id: str, user_id: str = Depends(get_current_user_id)
) -> list[MessagePublic]:
    """Historique (chiffré) d'un salon, réservé à ses membres."""
    await _get_membership_or_404(room_id, user_id)

    cursor = db.messages.find({"room_id": room_id}).sort("created_at", 1)
    documents = await cursor.to_list(length=200)
    return [_to_message_public(document) for document in documents]


@router.post(
    "/{room_id}/messages",
    response_model=MessagePublic,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require_csrf)],
)
async def send_message(
    room_id: str, payload: MessageCreate, user_id: str = Depends(get_current_user_id)
) -> MessagePublic:
    """Stocke un message chiffré et le publie en temps réel aux membres connectés."""
    await _get_membership_or_404(room_id, user_id)

    document: dict[str, Any] = {
        "room_id": room_id,
        "sender_id": user_id,
        "ciphertext": payload.ciphertext,
        "iv": payload.iv,
        "created_at": datetime.now(UTC),
    }
    result = await db.messages.insert_one(document)
    document["_id"] = result.inserted_id

    message = _to_message_public(document)
    await redis_client.publish(room_channel(room_id), message.model_dump_json())
    return message
