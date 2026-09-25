from datetime import datetime, timezone

from bson import ObjectId
from fastapi import APIRouter, Depends, HTTPException, Query, WebSocket, WebSocketDisconnect, status
from pydantic import ValidationError

from app.auth.router import get_current_user
from app.auth.service import decode_access_token
from app.config import settings
from app.db import get_db
from app.messages.models import MessageCreate, MessagePage, MessageResponse
from app.messages.ws import manager
from app.ratelimit import hit
from app.salons.service import channel_exists, is_member

router = APIRouter(tags=["messages"])

MAX_PAGE_SIZE = 100


def _to_response(doc: dict) -> MessageResponse:
    return MessageResponse(
        id=str(doc["_id"]),
        salon_id=str(doc["salon_id"]),
        channel_id=str(doc["channel_id"]) if doc.get("channel_id") else None,
        sender_id=str(doc["sender_id"]),
        sender_username=doc["sender_username"],
        ciphertext=doc["ciphertext"],
        iv=doc["iv"],
        created_at=doc["created_at"],
    )


@router.get("/salons/{salon_id}/messages", response_model=MessagePage)
async def get_messages(
    salon_id: str,
    limit: int = Query(default=50, ge=1, le=MAX_PAGE_SIZE),
    before: str | None = Query(default=None, description="ID du plus ancien message déjà chargé"),
    channel_id: str | None = Query(default=None),
    user: dict = Depends(get_current_user),
):
    """Historique paginé, du plus récent au plus ancien (curseur `before`)."""
    if not ObjectId.is_valid(salon_id):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid salon ID")
    if not await is_member(salon_id, str(user["_id"])):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not a member")

    query: dict = {"salon_id": ObjectId(salon_id)}
    if channel_id:
        if not ObjectId.is_valid(channel_id):
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid channel ID")
        query["channel_id"] = ObjectId(channel_id)
    if before:
        if not ObjectId.is_valid(before):
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid cursor")
        query["_id"] = {"$lt": ObjectId(before)}

    db = get_db()
    # On demande un élément de plus pour savoir s'il reste des pages.
    docs = await db.messages.find(query).sort("_id", -1).limit(limit + 1).to_list(length=limit + 1)
    has_more = len(docs) > limit
    docs = docs[:limit]
    next_cursor = str(docs[-1]["_id"]) if docs and has_more else None
    # Renvoyé en ordre chronologique pour un affichage direct.
    docs.reverse()
    return MessagePage(
        messages=[_to_response(d) for d in docs],
        next_cursor=next_cursor,
        has_more=has_more,
    )


@router.post(
    "/salons/{salon_id}/messages",
    status_code=status.HTTP_201_CREATED,
    response_model=MessageResponse,
)
async def send_message(salon_id: str, data: MessageCreate, user: dict = Depends(get_current_user)):
    if not ObjectId.is_valid(salon_id):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid salon ID")
    if not await is_member(salon_id, str(user["_id"])):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not a member")

    allowed, retry_after = hit(f"msg:{user['_id']}", settings.rate_limit_message, settings.rate_limit_message_window)
    if not allowed:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Trop de messages envoyés. Ralentissez.",
            headers={"Retry-After": str(retry_after)},
        )

    channel_oid = None
    if data.channel_id:
        if not await channel_exists(salon_id, data.channel_id):
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Channel not found")
        channel_oid = ObjectId(data.channel_id)

    db = get_db()
    msg_doc = {
        "salon_id": ObjectId(salon_id),
        "channel_id": channel_oid,
        "sender_id": user["_id"],
        "sender_username": user["username"],
        "ciphertext": data.ciphertext,
        "iv": data.iv,
        "created_at": datetime.now(timezone.utc),
    }
    result = await db.messages.insert_one(msg_doc)
    msg_doc["_id"] = result.inserted_id
    response = _to_response(msg_doc)
    await manager.broadcast(salon_id, response.model_dump(mode="json"))
    return response


@router.websocket("/ws/{salon_id}")
async def websocket_endpoint(websocket: WebSocket, salon_id: str):
    token = websocket.query_params.get("token")
    if not token:
        await websocket.close(code=4001, reason="Missing token")
        return
    payload = decode_access_token(token)
    if not payload or payload.get("type") == "refresh":
        await websocket.close(code=4001, reason="Invalid token")
        return
    user_id = payload["sub"]
    if not await is_member(salon_id, user_id):
        await websocket.close(code=4003, reason="Not a member")
        return

    db = get_db()
    user = await db.users.find_one({"_id": ObjectId(user_id)})
    if not user:
        await websocket.close(code=4001, reason="User not found")
        return

    await manager.connect(salon_id, websocket)
    try:
        while True:
            raw = await websocket.receive_json()
            try:
                data = MessageCreate(**raw)
            except (ValidationError, TypeError):
                await websocket.send_json({"error": "Message invalide"})
                continue

            allowed, retry_after = hit(
                f"msg:{user_id}", settings.rate_limit_message, settings.rate_limit_message_window
            )
            if not allowed:
                await websocket.send_json({"error": "Trop de messages", "retry_after": retry_after})
                continue

            channel_oid = None
            if data.channel_id:
                if not await channel_exists(salon_id, data.channel_id):
                    await websocket.send_json({"error": "Canal introuvable"})
                    continue
                channel_oid = ObjectId(data.channel_id)

            msg_doc = {
                "salon_id": ObjectId(salon_id),
                "channel_id": channel_oid,
                "sender_id": ObjectId(user_id),
                "sender_username": user["username"],
                "ciphertext": data.ciphertext,
                "iv": data.iv,
                "created_at": datetime.now(timezone.utc),
            }
            result = await db.messages.insert_one(msg_doc)
            msg_doc["_id"] = result.inserted_id
            await manager.broadcast(salon_id, _to_response(msg_doc).model_dump(mode="json"))
    except WebSocketDisconnect:
        manager.disconnect(salon_id, websocket)
    except Exception:  # noqa: BLE001 - toute erreur doit libérer la connexion proprement
        manager.disconnect(salon_id, websocket)
