from datetime import datetime, timezone

from bson import ObjectId
from fastapi import APIRouter, Depends, HTTPException, Query, WebSocket, WebSocketDisconnect, status
from pydantic import ValidationError

from app.auth.router import get_current_user
from app.auth.service import decode_access_token
from app.config import settings
from app.db import get_db
from app.messages.models import MessageCreate, MessageEdit, MessagePage, MessageResponse
from app.messages.ws import manager
from app.ratelimit import hit
from app.salons.service import channel_exists, is_member

router = APIRouter(tags=["messages"])

MAX_PAGE_SIZE = 100

# Le corps d'un message supprimé est remplacé par ce marqueur : le texte
# chiffré est effacé de la base, pas seulement masqué à l'affichage.
DELETED_PLACEHOLDER = ""


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
        edited_at=doc.get("edited_at"),
        deleted=bool(doc.get("deleted", False)),
    )


def _enforce_message_rate(user_id) -> None:
    allowed, retry_after = hit(f"msg:{user_id}", settings.rate_limit_message, settings.rate_limit_message_window)
    if not allowed:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Trop de messages envoyés. Ralentissez.",
            headers={"Retry-After": str(retry_after)},
        )


async def _require_member(salon_id: str, user: dict) -> None:
    if not ObjectId.is_valid(salon_id):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid salon ID")
    if not await is_member(salon_id, str(user["_id"])):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not a member")


async def _own_message(salon_id: str, message_id: str, user: dict) -> dict:
    """Charge un message et vérifie que l'utilisateur en est bien l'auteur."""
    if not ObjectId.is_valid(message_id):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid message ID")
    db = get_db()
    doc = await db.messages.find_one({"_id": ObjectId(message_id), "salon_id": ObjectId(salon_id)})
    if not doc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Message not found")
    if str(doc["sender_id"]) != str(user["_id"]):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Seul l'auteur peut modifier ou supprimer son message",
        )
    if doc.get("deleted"):
        raise HTTPException(status_code=status.HTTP_410_GONE, detail="Message déjà supprimé")
    return doc


@router.get("/salons/{salon_id}/messages", response_model=MessagePage)
async def get_messages(
    salon_id: str,
    limit: int = Query(default=50, ge=1, le=MAX_PAGE_SIZE),
    before: str | None = Query(default=None, description="ID du plus ancien message déjà chargé"),
    channel_id: str | None = Query(default=None),
    user: dict = Depends(get_current_user),
):
    """Historique paginé, du plus récent au plus ancien (curseur `before`)."""
    await _require_member(salon_id, user)

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
    await _require_member(salon_id, user)
    _enforce_message_rate(user["_id"])

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
        "edited_at": None,
        "deleted": False,
    }
    result = await db.messages.insert_one(msg_doc)
    msg_doc["_id"] = result.inserted_id
    response = _to_response(msg_doc)
    await manager.broadcast(salon_id, {"type": "message", **response.model_dump(mode="json")})
    return response


@router.patch("/salons/{salon_id}/messages/{message_id}", response_model=MessageResponse)
async def edit_message(
    salon_id: str,
    message_id: str,
    data: MessageEdit,
    user: dict = Depends(get_current_user),
):
    """Remplace l'enveloppe chiffrée d'un message par une nouvelle."""
    await _require_member(salon_id, user)
    doc = await _own_message(salon_id, message_id, user)

    db = get_db()
    edited_at = datetime.now(timezone.utc)
    await db.messages.update_one(
        {"_id": doc["_id"]},
        {"$set": {"ciphertext": data.ciphertext, "iv": data.iv, "edited_at": edited_at}},
    )
    doc.update({"ciphertext": data.ciphertext, "iv": data.iv, "edited_at": edited_at})
    response = _to_response(doc)
    await manager.broadcast(salon_id, {"type": "message_updated", **response.model_dump(mode="json")})
    return response


@router.delete("/salons/{salon_id}/messages/{message_id}")
async def delete_message(salon_id: str, message_id: str, user: dict = Depends(get_current_user)):
    """Efface le contenu chiffré et marque le message comme supprimé."""
    await _require_member(salon_id, user)
    doc = await _own_message(salon_id, message_id, user)

    db = get_db()
    await db.messages.update_one(
        {"_id": doc["_id"]},
        {
            "$set": {
                # Le texte chiffré est réellement retiré de la base :
                # une suppression purement visuelle n'en serait pas une.
                "ciphertext": DELETED_PLACEHOLDER,
                "iv": DELETED_PLACEHOLDER,
                "deleted": True,
                "deleted_at": datetime.now(timezone.utc),
            }
        },
    )
    await manager.broadcast(salon_id, {"type": "message_deleted", "id": message_id, "salon_id": salon_id})
    return {"detail": "Message supprimé"}


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

    await manager.connect(salon_id, websocket, user_id, user["username"])
    await manager.broadcast_presence(salon_id)
    try:
        while True:
            raw = await websocket.receive_json()
            kind = raw.get("type", "message") if isinstance(raw, dict) else "message"

            if kind == "typing":
                # Diffusé aux autres seulement : se voir soi-même taper n'a pas de sens.
                await manager.broadcast(
                    salon_id,
                    {"type": "typing", "username": user["username"], "channel_id": raw.get("channel_id")},
                    exclude=websocket,
                )
                continue

            if kind != "message":
                await websocket.send_json({"type": "error", "error": "Type de message inconnu"})
                continue

            try:
                data = MessageCreate(**{k: v for k, v in raw.items() if k != "type"})
            except (ValidationError, TypeError, AttributeError):
                await websocket.send_json({"type": "error", "error": "Message invalide"})
                continue

            allowed, retry_after = hit(
                f"msg:{user_id}", settings.rate_limit_message, settings.rate_limit_message_window
            )
            if not allowed:
                await websocket.send_json({"type": "error", "error": "Trop de messages", "retry_after": retry_after})
                continue

            channel_oid = None
            if data.channel_id:
                if not await channel_exists(salon_id, data.channel_id):
                    await websocket.send_json({"type": "error", "error": "Canal introuvable"})
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
                "edited_at": None,
                "deleted": False,
            }
            result = await db.messages.insert_one(msg_doc)
            msg_doc["_id"] = result.inserted_id
            await manager.broadcast(salon_id, {"type": "message", **_to_response(msg_doc).model_dump(mode="json")})
    except WebSocketDisconnect:
        manager.disconnect(salon_id, websocket)
        await manager.broadcast_presence(salon_id)
    except Exception:  # noqa: BLE001 - toute erreur doit libérer la connexion proprement
        manager.disconnect(salon_id, websocket)
        await manager.broadcast_presence(salon_id)
