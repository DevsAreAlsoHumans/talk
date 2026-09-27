"""Envoi et reception des enveloppes chiffrees (REST + repli par polling)."""

from fastapi import APIRouter, Depends, Query
from redis import Redis

from app.api.deps import channel_access, current_user, require_csrf
from app.config import get_settings
from app.db import get_redis
from app.repositories import messages
from app.schemas_chat import MessageEnvelopeIn, MessageEnvelopeOut, MessagePage
from app.security.ratelimit import enforce_rate_limit
from app.ws import manager

router = APIRouter(tags=["messages"])

MAX_LIMIT = 100
DEFAULT_LIMIT = 50


def _check_rate_limit(redis: Redis, user_id: str) -> None:
    settings = get_settings()
    enforce_rate_limit(
        redis,
        f"ratelimit:message:{user_id}",
        limit=settings.rate_limit_message_max,
        window=settings.rate_limit_message_window,
    )


@router.post(
    "/channels/{channel_id}/messages",
    response_model=MessageEnvelopeOut,
    status_code=201,
    dependencies=[Depends(require_csrf)],
)
async def send_message(
    channel_id: str,
    payload: MessageEnvelopeIn,
    channel: dict = Depends(channel_access),
    redis: Redis = Depends(get_redis),
    user: dict = Depends(current_user),
) -> MessageEnvelopeOut:
    """Le serveur stocke l'enveloppe telle quelle : il ne peut pas la lire."""
    _check_rate_limit(redis, user["id"])
    envelope = messages.store_message(
        redis,
        channel_id=channel_id,
        sender_id=user["id"],
        ciphertext=payload.ciphertext,
        iv=payload.iv,
        key_version=payload.key_version,
    )
    await manager.broadcast(channel_id, {"type": "message", "message": envelope})
    return MessageEnvelopeOut(**envelope)


@router.get("/channels/{channel_id}/messages", response_model=MessagePage)
def read_history(
    channel_id: str,
    before: int | None = Query(default=None, ge=1, description="sequence exclusive"),
    limit: int = Query(default=DEFAULT_LIMIT, ge=1, le=MAX_LIMIT),
    _channel: dict = Depends(channel_access),
    redis: Redis = Depends(get_redis),
) -> MessagePage:
    """Historique pagine, du plus ancien au plus recent."""
    return MessagePage(
        messages=[
            MessageEnvelopeOut(**envelope)
            for envelope in messages.list_messages(redis, channel_id, limit=limit, before=before)
        ],
        latest_seq=messages.latest_sequence(redis, channel_id),
    )


@router.get("/channels/{channel_id}/messages/poll", response_model=MessagePage)
def poll_messages(
    channel_id: str,
    after: int = Query(default=0, ge=0, description="derniere sequence connue"),
    limit: int = Query(default=MAX_LIMIT, ge=1, le=MAX_LIMIT),
    _channel: dict = Depends(channel_access),
    redis: Redis = Depends(get_redis),
) -> MessagePage:
    """Repli temps reel : recuperation courte et incrementale.

    Le client rappelle cet endpoint avec la sequence du dernier message recu ;
    la reponse est vide si rien n'a bouge, ce qui evite de recharger l'historique.
    """
    found = messages.messages_since(redis, channel_id, after, limit)
    return MessagePage(
        messages=[MessageEnvelopeOut(**envelope) for envelope in found],
        latest_seq=messages.latest_sequence(redis, channel_id),
    )
