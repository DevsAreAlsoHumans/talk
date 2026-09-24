import time
from typing import Any, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status

from app.dependencies import get_current_user, get_store, require_csrf
from app.realtime import ConnectionManager
from app.schemas import MessageCreateRequest
from app.storage import RedisStore

router = APIRouter(prefix="/api/channels", tags=["messages"])


async def _channel_context(
    store: RedisStore, channel_id: str, user_id: str
) -> tuple[dict[str, Any], dict[str, Any]]:
    channel = await store.get_channel(channel_id)
    if channel is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Canal introuvable")
    room = await store.get_room(channel["room_id"])
    if room is None or not await store.is_room_member(channel["room_id"], user_id):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Canal introuvable")
    return channel, room


async def _message_with_sender(store: RedisStore, message: dict[str, Any]) -> dict[str, Any]:
    sender = await store.get_user(message["sender_id"])
    return {**message, "sender": sender}


@router.get("/{channel_id}/messages", summary="Lire les messages chiffrés")
async def list_messages(
    channel_id: str,
    limit: int = Query(default=50, ge=1, le=100),
    before: Optional[int] = Query(default=None, ge=1),
    user: dict[str, Any] = Depends(get_current_user),
    store: RedisStore = Depends(get_store),
) -> dict[str, Any]:
    channel, _ = await _channel_context(store, channel_id, user["id"])
    messages, next_cursor = await store.list_messages(channel["id"], before=before, limit=limit)
    return {
        "messages": [await _message_with_sender(store, message) for message in messages],
        "next_cursor": next_cursor,
    }


@router.post(
    "/{channel_id}/messages",
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require_csrf)],
    summary="Stocker un message chiffré",
)
async def create_message(
    channel_id: str,
    payload: MessageCreateRequest,
    request: Request,
    user: dict[str, Any] = Depends(get_current_user),
    store: RedisStore = Depends(get_store),
) -> dict[str, Any]:
    channel, room = await _channel_context(store, channel_id, user["id"])
    if payload.key_version != room["key_version"]:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="La version de clé du salon n'est pas à jour",
        )

    message = {
        **payload.model_dump(mode="json"),
        "sender_id": user["id"],
        "room_id": room["id"],
        "channel_id": channel["id"],
        "created_at": int(time.time() * 1000),
    }
    created, _ = await store.save_message(message)
    if not created:
        existing = await store.get_message(str(payload.client_id))
        if (
            existing is None
            or existing["sender_id"] != user["id"]
            or existing["channel_id"] != channel_id
        ):
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Cet identifiant de message est déjà utilisé",
            )
        message = existing
    else:
        stored = await store.get_message(str(payload.client_id))
        if stored is None:
            raise HTTPException(status_code=500, detail="Message introuvable après stockage")
        message = stored

    member_ids = await store.all_room_member_ids(room["id"])
    manager: ConnectionManager = request.app.state.manager
    await manager.broadcast_to_users(
        member_ids,
        {"type": "message.created", "message": message},
    )
    return await _message_with_sender(store, message)
