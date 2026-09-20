"""Salons : listing, création, membres, join, clés de salon enveloppées.

Contrôles d'accès : 404 si le salon n'existe pas, 403 si l'appelant n'en est
pas membre (sauf join).
"""

from __future__ import annotations

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException
from redis import Redis

from app.api.deps import get_current_user, get_room_or_404, require_member
from app.db.redis import get_redis
from app.realtime.hub import InProcessHub, get_hub
from app.repositories import rooms, users
from app.schemas import KeyWrapRequest, MemberPublic, Room, RoomCreate

router = APIRouter(prefix="/rooms", tags=["rooms"])


@router.get("", response_model=list[Room])
def list_rooms(
    user: dict = Depends(get_current_user),
    redis: Redis = Depends(get_redis),
) -> list[dict]:
    """Salons dont l'utilisateur courant est membre."""
    return rooms.list_for_user(redis, user["id"])


@router.post("", response_model=Room, status_code=201)
def create_room(
    body: RoomCreate,
    user: dict = Depends(get_current_user),
    redis: Redis = Depends(get_redis),
) -> dict:
    """Crée un salon ; le créateur en devient le premier membre."""
    return rooms.create_room(redis, body.name, user["id"])


@router.get("/{room_id}/members", response_model=list[MemberPublic])
def list_members(
    room_id: str,
    user: dict = Depends(get_current_user),
    redis: Redis = Depends(get_redis),
) -> list[dict]:
    """Liste des membres du salon (id, username, public_key)."""
    get_room_or_404(redis, room_id)
    require_member(redis, room_id, user["id"])
    return rooms.list_members(redis, room_id)


@router.post("/{room_id}/join", response_model=Room)
def join_room(
    room_id: str,
    background: BackgroundTasks,
    user: dict = Depends(get_current_user),
    redis: Redis = Depends(get_redis),
    hub: InProcessHub = Depends(get_hub),
) -> dict:
    """Rejoint un salon (404 si inconnu, 409 si déjà membre)."""
    room = get_room_or_404(redis, room_id)
    if rooms.is_member(redis, room_id, user["id"]):
        raise HTTPException(status_code=409, detail="Already a member of this room")
    rooms.add_member(redis, room_id, user["id"])

    background.add_task(
        hub.publish,
        room_id,
        {
            "type": "member_joined",
            "payload": {"room_id": room_id, "member": users.to_public(user)},
        },
    )
    return room


@router.post("/{room_id}/keys", status_code=201)
def store_wrapped_key(
    room_id: str,
    body: KeyWrapRequest,
    background: BackgroundTasks,
    user: dict = Depends(get_current_user),
    redis: Redis = Depends(get_redis),
    hub: InProcessHub = Depends(get_hub),
) -> dict:
    """Enregistre la copie de la clé de salon enveloppée pour un membre.

    L'auteur comme la cible doivent être membres du salon, sinon 403. Le
    serveur ne reçoit que le chiffré (``wrapped_key``) — jamais la clé en
    clair ni la clé privée. Un événement ``room_key`` est diffusé aux abonnés
    du salon : la copie étant chiffrée pour la clé publique de la cible, seul
    le membre ciblé peut la déchiffrer (diffusion sûre).
    """
    get_room_or_404(redis, room_id)
    require_member(redis, room_id, user["id"])
    if not rooms.is_member(redis, room_id, body.target_user_id):
        raise HTTPException(status_code=403, detail="Target user is not a member of this room")
    rooms.store_wrapped_key(redis, room_id, body.target_user_id, body.wrapped_key)
    background.add_task(
        hub.publish,
        room_id,
        {
            "type": "room_key",
            "payload": {
                "room_id": room_id,
                "target_user_id": body.target_user_id,
                "wrapped_key": body.wrapped_key,
            },
        },
    )
    return {"room_id": room_id, "target_user_id": body.target_user_id, "stored": True}
