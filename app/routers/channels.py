"""Routeur des canaux : fils textuels chiffrés dans un salon (modèle Discord).

E2EE : chaque canal contient des blobs opaques (même clé de salon enveloppée
par membre) — le serveur ne fait que contrôler l'appartenance et rejouer des
données illisibles. Les messages sont isolés canal par canal (seq par canal).
"""

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, Response, status

from ..db import Database, get_db
from ..deps import get_current_user, require_csrf
from ..models import ChannelCreate, ChannelPublic, MessageOut, UserPublic
from .rooms import _member_room_or_error

router = APIRouter(prefix="/api/rooms", tags=["channels"])

DbDep = Annotated[Database, Depends(get_db)]
CurrentUser = Annotated[UserPublic, Depends(get_current_user)]


def _channel_public(channel: dict) -> ChannelPublic:
    return ChannelPublic(
        id=str(channel["_id"]),
        name=channel["name"],
        created_at=channel["created_at"],
    )


@router.get("/{room_id}/channels", response_model=list[ChannelPublic])
async def list_channels(room_id: str, user: CurrentUser, db: DbDep):
    """Canaux du salon (réservés aux membres)."""
    await _member_room_or_error(db, room_id, user.username)
    rows = await db.list_channels(room_id)
    return [_channel_public(c) for c in rows]


@router.post(
    "/{room_id}/channels", status_code=status.HTTP_201_CREATED, response_model=ChannelPublic
)
async def create_channel(
    room_id: str,
    payload: ChannelCreate,
    user: CurrentUser,
    db: DbDep,
    _: None = Depends(require_csrf),  # mutation : CSRF obligatoire
):
    """Crée un canal dans le salon. Le nom est validé (pas de doublon)."""
    await _member_room_or_error(db, room_id, user.username)
    channel = await db.create_channel(room_id, payload.name)
    if channel is None:
        raise HTTPException(status_code=409, detail="Nom de canal déjà utilisé")
    return _channel_public(channel)


@router.get("/{room_id}/channels/{channel_id}/messages", response_model=list[MessageOut])
async def get_channel_messages(
    room_id: str,
    channel_id: str,
    user: CurrentUser,
    db: DbDep,
    after: int | None = Query(default=None, ge=0),
    limit: int = Query(default=200, ge=1, le=500),
):
    """Historique chiffré du canal : blobs rejoués tels quels."""
    await _member_room_or_error(db, room_id, user.username)
    channel = await db.get_channel(room_id, channel_id)
    if channel is None:
        raise HTTPException(status_code=404, detail="Canal introuvable")
    rows = await db.get_channel_messages(room_id, channel_id, after=after, limit=limit)
    return [MessageOut(**r) for r in rows]


@router.delete("/{room_id}/channels/{channel_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_channel(
    room_id: str,
    channel_id: str,
    user: CurrentUser,
    db: DbDep,
    _: None = Depends(require_csrf),
):
    """Supprime un canal — réservé au créateur du salon (au moins un canal reste)."""
    room = await _member_room_or_error(db, room_id, user.username)
    if user.username != room["owner_id"]:
        raise HTTPException(status_code=403, detail="Réservé au créateur du salon")
    channel = await db.get_channel(room_id, channel_id)
    if channel is None:
        raise HTTPException(status_code=404, detail="Canal introuvable")
    channels = await db.list_channels(room_id)
    if len(channels) <= 1:
        raise HTTPException(status_code=400, detail="Un salon doit garder au moins un canal")
    await db.delete_channel(room_id, channel_id)
    return Response(status_code=status.HTTP_204_NO_CONTENT)
