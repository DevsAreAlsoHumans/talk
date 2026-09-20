"""Messages des salons : historique (polling) et envoi, avec diffusion WS.

Le serveur ne manipule que du chiffré (nonce + ciphertext, en base64). Après
création, un événement ``new_message`` est diffusé aux abonnés WebSocket.
"""

from __future__ import annotations

from fastapi import APIRouter, BackgroundTasks, Depends, Query
from redis import Redis

from app.api.deps import get_current_user, get_room_or_404, require_member
from app.db.redis import get_redis
from app.realtime.hub import InProcessHub, get_hub
from app.repositories import messages
from app.schemas import MessageCreate

router = APIRouter(prefix="/rooms", tags=["messages"])

__all__ = ["router"]


@router.get("/{room_id}/messages", response_model=dict)
def list_messages(
    room_id: str,
    after: int = Query(default=0, ge=0),
    user: dict = Depends(get_current_user),
    redis: Redis = Depends(get_redis),
) -> dict:
    """Historique des messages (chiffrés) avec ``seq`` > ``after``, triés."""
    get_room_or_404(redis, room_id)
    require_member(redis, room_id, user["id"])
    return {"messages": messages.list_messages_after(redis, room_id, after)}


@router.post("/{room_id}/messages", response_model=dict, status_code=201)
def post_message(
    room_id: str,
    body: MessageCreate,
    background: BackgroundTasks,
    user: dict = Depends(get_current_user),
    redis: Redis = Depends(get_redis),
    hub: InProcessHub = Depends(get_hub),
) -> dict:
    """Crée un message chiffré et diffuse ``new_message`` aux abonnés du salon."""
    get_room_or_404(redis, room_id)
    require_member(redis, room_id, user["id"])
    message = messages.create_message(redis, room_id, user["id"], body.nonce, body.ciphertext)
    background.add_task(
        hub.publish,
        room_id,
        {"type": "new_message", "payload": message},
    )
    return {"message": message}
