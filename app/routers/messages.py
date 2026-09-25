"""Messages : envoi et historique. Le serveur ne manipule que du texte chiffré."""

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, HTTPException, Query

from app.config import Settings
from app.deps import (
    AuthDep,
    EventBusDep,
    MessagesDep,
    NotificationsDep,
    RedisDep,
    RoomsDep,
    SettingsDep,
)
from app.notifications import THREAD_ROOM, notify_message_sent
from app.schemas import MessageOut, MessagePage, SendMessageRequest
from app.security.rate_limit import is_rate_limited

router = APIRouter(prefix="/api/rooms/{room_id}/messages", tags=["messages"])


async def _require_member(rooms: RoomsDep, room_id: UUID, user_id: str) -> dict[str, str]:
    """Renvoie le salon si l'utilisateur en est membre, 404 sinon (comme s'il n'existait pas)."""
    room = await rooms.get(str(room_id))
    if room is None or not await rooms.is_member(str(room_id), user_id):
        raise HTTPException(status_code=404, detail="Salon introuvable")
    return room


@router.get("", response_model=MessagePage)
async def get_history(
    room_id: UUID,
    auth: AuthDep,
    rooms: RoomsDep,
    messages: MessagesDep,
    before: Annotated[int | None, Query(ge=1)] = None,
    limit: Annotated[int, Query(ge=1, le=100)] = 50,
) -> dict:
    await _require_member(rooms, room_id, auth.user["id"])
    page, has_more = await messages.history(str(room_id), before=before, limit=limit)
    return {"messages": page, "has_more": has_more}


@router.post("", status_code=201, response_model=MessageOut)
async def send_message(
    room_id: UUID,
    body: SendMessageRequest,
    auth: AuthDep,
    rooms: RoomsDep,
    messages: MessagesDep,
    notifications: NotificationsDep,
    redis: RedisDep,
    settings: SettingsDep,
    bus: EventBusDep,
) -> dict:
    room = await _require_member(rooms, room_id, auth.user["id"])
    _enforce_message_rate(
        await is_rate_limited(
            redis, f"rl:message:{auth.user['id']}", settings.message_limit, settings.message_window_seconds
        ),
        settings,
    )

    if not await messages.reserve_iv(str(room_id), body.iv):
        raise HTTPException(status_code=409, detail="IV déjà utilisé dans ce salon")

    message = await messages.append(
        thread_id=str(room_id),
        sender_id=auth.user["id"],
        sender_username=auth.user["username"],
        iv=body.iv,
        ciphertext=body.ciphertext,
        kind=body.kind,
        mime=body.mime,
    )
    member_ids = await rooms.member_ids(str(room_id))
    await bus.publish({"type": "message", "message": message}, member_ids)
    await notify_message_sent(
        notifications,
        bus,
        recipients=member_ids,
        sender_id=auth.user["id"],
        sender_username=auth.user["username"],
        thread_kind=THREAD_ROOM,
        thread_id=str(room_id),
        thread_label=room["name"],
        message=message,
    )
    return message


def _enforce_message_rate(limited: bool, settings: Settings) -> None:
    if limited:
        raise HTTPException(
            status_code=429,
            detail="Trop de messages envoyés, ralentissez",
            headers={"Retry-After": str(settings.message_window_seconds)},
        )
