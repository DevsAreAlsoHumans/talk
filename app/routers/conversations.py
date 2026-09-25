"""Conversations directes entre deux amis : création, détail, messages chiffrés.

Une conversation est chiffrée de bout en bout exactement comme un salon : une clé
AES-256 par conversation, enveloppée (ECDH éphémère → HKDF → AES-GCM) pour les deux
participants uniquement. Le serveur ne stocke que des enveloppes et du texte chiffré,
et ne publie un événement qu'aux deux membres de la conversation.

Une conversation ne peut être créée qu'entre deux amis, et une seule existe par
paire : l'existence est révélée par un 409, les accès extérieurs donnent 404.
"""

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, HTTPException, Query

from app.deps import (
    AuthDep,
    ConversationMessagesDep,
    ConversationsDep,
    EventBusDep,
    FriendsDep,
    NotificationsDep,
    RedisDep,
    SettingsDep,
    UsersDep,
)
from app.notifications import THREAD_CONVERSATION, notify_message_sent
from app.schemas import (
    ConversationDetail,
    ConversationMessageOut,
    ConversationMessagePage,
    ConversationSummary,
    CreateConversationRequest,
    SendMessageRequest,
)
from app.security.rate_limit import is_rate_limited

router = APIRouter(prefix="/api/conversations", tags=["conversations"])


def _profile(row: dict[str, str]) -> dict[str, str]:
    """Profil visible d'un participant (métadonnées en clair, jamais les clés)."""
    return {
        "id": row["id"],
        "username": row["username"],
        "public_key": row["public_key"],
        "display_name": row["display_name"],
        "bio": row["bio"],
    }


async def _require_member(convs: ConversationsDep, conv_id: UUID, user_id: str) -> dict[str, str]:
    conv = await convs.get(str(conv_id))
    if conv is None or not await convs.is_member(str(conv_id), user_id):
        raise HTTPException(status_code=404, detail="Conversation introuvable")
    return conv


async def _peer_profile(
    convs: ConversationsDep, users: UsersDep, conv: dict[str, str], user_id: str
) -> dict[str, str] | None:
    peer_id = await convs.peer_id(conv["id"], user_id)
    peer = await users.get(peer_id) if peer_id else None
    return _profile(peer) if peer else None


def _as_conversation_message(message: dict) -> dict:
    """Renomme l'identifiant de fil (``room_id`` interne) en ``conversation_id``, sans le muter."""
    renamed = {**message, "conversation_id": message["room_id"]}
    del renamed["room_id"]
    return renamed


@router.get("", response_model=list[ConversationSummary])
async def list_conversations(auth: AuthDep, convs: ConversationsDep, users: UsersDep) -> list[dict]:
    result = []
    for conv_id in await convs.conv_ids(auth.user["id"]):
        conv = await convs.get(conv_id)
        if conv is None:
            continue
        peer = await _peer_profile(convs, users, conv, auth.user["id"])
        if peer is None:
            continue
        result.append({**conv, "peer": peer, "member_count": 2})
    return sorted(result, key=lambda conv: conv["created_at"])


@router.post("", status_code=201, response_model=ConversationDetail)
async def create_conversation(
    body: CreateConversationRequest,
    auth: AuthDep,
    friends: FriendsDep,
    convs: ConversationsDep,
    users: UsersDep,
) -> dict:
    """Ouvre une conversation avec un ami (réservé aux amis, une par paire)."""
    peer = await users.get_by_username(body.username)
    if peer is None:
        raise HTTPException(status_code=404, detail="Utilisateur introuvable")
    if peer["id"] == auth.user["id"]:
        raise HTTPException(status_code=400, detail="Impossible de se messageer soi-même")
    if not await friends.is_friend(auth.user["id"], peer["id"]):
        raise HTTPException(status_code=403, detail="Conversation réservée aux amis")

    conv, created = await convs.create(
        initiator_id=auth.user["id"],
        peer_id=peer["id"],
        wrapped_key_initiator=body.wrapped_key.model_dump(),
        wrapped_key_peer=body.peer_wrapped_key.model_dump(),
    )
    if not created:
        raise HTTPException(status_code=409, detail="Conversation déjà existante")
    return {**conv, "peer": _profile(peer), "wrapped_key": body.wrapped_key.model_dump()}


@router.get("/{conv_id}", response_model=ConversationDetail)
async def get_conversation(conv_id: UUID, auth: AuthDep, convs: ConversationsDep, users: UsersDep) -> dict:
    conv = await _require_member(convs, conv_id, auth.user["id"])
    peer = await _peer_profile(convs, users, conv, auth.user["id"])
    wrapped_key = await convs.get_wrapped_key(str(conv_id), auth.user["id"])
    return {**conv, "peer": peer, "wrapped_key": wrapped_key}


@router.get("/{conv_id}/messages", response_model=ConversationMessagePage)
async def get_history(
    conv_id: UUID,
    auth: AuthDep,
    convs: ConversationsDep,
    messages: ConversationMessagesDep,
    before: Annotated[int | None, Query(ge=1)] = None,
    limit: Annotated[int, Query(ge=1, le=100)] = 50,
) -> dict:
    await _require_member(convs, conv_id, auth.user["id"])
    page, has_more = await messages.history(str(conv_id), before=before, limit=limit)
    return {
        "messages": [_as_conversation_message(message) for message in page],
        "has_more": has_more,
    }


@router.post("/{conv_id}/messages", status_code=201, response_model=ConversationMessageOut)
async def send_message(
    conv_id: UUID,
    body: SendMessageRequest,
    auth: AuthDep,
    convs: ConversationsDep,
    messages: ConversationMessagesDep,
    notifications: NotificationsDep,
    redis: RedisDep,
    settings: SettingsDep,
    bus: EventBusDep,
) -> dict:
    await _require_member(convs, conv_id, auth.user["id"])
    if await is_rate_limited(
        redis, f"rl:message:{auth.user['id']}", settings.message_limit, settings.message_window_seconds
    ):
        raise HTTPException(
            status_code=429,
            detail="Trop de messages envoyés, ralentissez",
            headers={"Retry-After": str(settings.message_window_seconds)},
        )

    if not await messages.reserve_iv(str(conv_id), body.iv):
        raise HTTPException(status_code=409, detail="IV déjà utilisé dans cette conversation")

    message = await messages.append(
        thread_id=str(conv_id),
        sender_id=auth.user["id"],
        sender_username=auth.user["username"],
        iv=body.iv,
        ciphertext=body.ciphertext,
        kind=body.kind,
        mime=body.mime,
    )
    member_ids = await convs.member_ids(str(conv_id))
    await bus.publish({"type": "dm", "message": _as_conversation_message(message)}, member_ids)
    await notify_message_sent(
        notifications,
        bus,
        recipients=member_ids,
        sender_id=auth.user["id"],
        sender_username=auth.user["username"],
        thread_kind=THREAD_CONVERSATION,
        thread_id=str(conv_id),
        thread_label=auth.user["username"],  # le seul destinataire est l'interlocuteur : son pseudo le nomme
        message=message,
    )
    return _as_conversation_message(message)
