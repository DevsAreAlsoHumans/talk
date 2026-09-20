"""Routeur des salons : création, invitation, clés de salon et historique.

E2EE : le serveur ne stocke QUE des blobs opaques — clés « enveloppées »
individuellement pour chaque membre et messages chiffrés. Le déchiffrement
n'existe que côté client.
"""

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Response, status

from ..db import Database, get_db
from ..deps import get_current_user, require_csrf
from ..models import (
    InvitePayload,
    KeyBlob,
    MemberPublic,
    RoomCreate,
    RoomKeyShare,
    RoomMembers,
    RoomPublic,
    UserPublic,
)

router = APIRouter(prefix="/api/rooms", tags=["rooms"])

DbDep = Annotated[Database, Depends(get_db)]
CurrentUser = Annotated[UserPublic, Depends(get_current_user)]


def _room_public(room: dict) -> RoomPublic:
    return RoomPublic(
        id=str(room["_id"]),
        name=room["name"],
        owner_id=room["owner_id"],
        created_at=room["created_at"],
    )


async def _member_room_or_error(db: Database, room_id: str, username: str) -> dict:
    """Salon + appartenance, sinon 404/403 sans fuite d'existence inutile."""
    room = await db.get_room_by_id(room_id)
    if room is None:
        raise HTTPException(status_code=404, detail="Salon introuvable")
    if username not in room["members"]:
        raise HTTPException(status_code=403, detail="Vous n'êtes pas membre de ce salon")
    return room


@router.get("", response_model=list[RoomPublic])
async def list_rooms(user: CurrentUser, db: DbDep):
    """Salons dont l'utilisateur est membre (sidebar du client)."""
    rooms = await db.list_rooms_for_user(user.username)
    return [_room_public(r) for r in rooms]


@router.post("", status_code=status.HTTP_201_CREATED, response_model=RoomPublic)
async def create_room(
    payload: RoomCreate,
    user: CurrentUser,
    db: DbDep,
    _: None = Depends(require_csrf),  # mutation : CSRF obligatoire
):
    room = await db.create_room(name=payload.name, owner_id=user.username)
    return _room_public(room)


@router.get("/{room_id}", response_model=RoomPublic)
async def get_room(
    room_id: str,
    user: CurrentUser,
    db: DbDep,
):
    room = await _member_room_or_error(db, room_id, user.username)
    return _room_public(room)


@router.post("/{room_id}/invite", response_model=RoomPublic)
async def invite(
    room_id: str,
    payload: InvitePayload,
    user: CurrentUser,
    db: DbDep,
    _: None = Depends(require_csrf),
):
    """Ajoute un membre — réservé au créateur du salon (idempotent)."""
    room = await db.get_room_by_id(room_id)
    if room is None:
        raise HTTPException(status_code=404, detail="Salon introuvable")
    if user.username != room["owner_id"]:
        raise HTTPException(status_code=403, detail="Réservé au créateur du salon")
    target = await db.get_user_by_username(payload.username)
    if target is None:
        raise HTTPException(status_code=404, detail="Utilisateur introuvable")
    await db.add_room_member(room_id, payload.username)
    room = await db.get_room_by_id(room_id)
    return _room_public(room)


@router.get("/{room_id}/members", response_model=RoomMembers)
async def list_members(room_id: str, user: CurrentUser, db: DbDep):
    """Membres + leurs clés publiques — pour l'enveloppement de la clé de salon."""
    room = await _member_room_or_error(db, room_id, user.username)
    members = []
    for username in room["members"]:
        pk = await db.get_public_key(username)
        members.append(MemberPublic(username=username, public_key=pk))
    return RoomMembers(owner_id=room["owner_id"], members=members)


@router.post("/{room_id}/keys", status_code=status.HTTP_204_NO_CONTENT)
async def share_room_key(
    room_id: str,
    payload: RoomKeyShare,
    user: CurrentUser,
    db: DbDep,
    _: None = Depends(require_csrf),
):
    """Stocke la clé de salon « enveloppée » pour un membre (blob opaque)."""
    room = await db.get_room_by_id(room_id)
    if room is None:
        raise HTTPException(status_code=404, detail="Salon introuvable")
    if user.username != room["owner_id"]:
        raise HTTPException(status_code=403, detail="Réservé au créateur du salon")
    if payload.to not in room["members"]:
        raise HTTPException(status_code=400, detail="Le destinataire n'est pas membre")
    await db.set_wrapped_key(room_id, payload.to, payload.blob.model_dump())
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.get("/{room_id}/keys/me", response_model=KeyBlob)
async def my_room_key(room_id: str, user: CurrentUser, db: DbDep):
    """Mon exemplaire enveloppé de la clé de salon (déchiffré côté client)."""
    await _member_room_or_error(db, room_id, user.username)
    blob = await db.get_wrapped_key(room_id, user.username)
    if blob is None:
        raise HTTPException(status_code=404, detail="Aucune clé de salon partagée pour vous")
    return KeyBlob(**blob)
