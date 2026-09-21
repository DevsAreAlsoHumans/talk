"""Salons : création, liste, détail, ajout de membres, avatars chiffrés.

Un salon n'est visible que de ses membres : pour les autres (ou s'il n'existe pas), la
réponse est identique (404), afin de ne pas révéler l'existence d'un salon.

Avatars : chaque membre chiffre son avatar avec la clé du salon (AES-GCM, IV réservé
dans la même base anti-réutilisation que les messages) et le serveur ne stocke que ce
chiffré : un membre peut le déchiffrer, le serveur jamais.
"""

from uuid import UUID

from fastapi import APIRouter, HTTPException

from app.deps import AuthDep, ConnectionManagerDep, EventBusDep, MessagesDep, RoomsDep, UsersDep
from app.repositories.rooms import ROLE_CO
from app.schemas import (
    AddMemberRequest,
    AvatarRequest,
    CreateRoomRequest,
    RoomDetail,
    RoomSummary,
    SetRoleRequest,
    UserPublic,
)

router = APIRouter(prefix="/api/rooms", tags=["rooms"])


async def _require_member(rooms: RoomsDep, room_id: UUID, user_id: str) -> dict[str, str]:
    room = await rooms.get(str(room_id))
    if room is None or not await rooms.is_member(str(room_id), user_id):
        raise HTTPException(status_code=404, detail="Salon introuvable")
    return room


async def _can_manage_members(rooms: RoomsDep, room: dict[str, str], user_id: str) -> bool:
    """Le chef (propriétaire) et les sous-chefs peuvent ajouter des membres."""
    if room["owner_id"] == user_id:
        return True
    return await rooms.get_role(room["id"], user_id) == ROLE_CO


@router.get("", response_model=list[RoomSummary])
async def list_rooms(auth: AuthDep, rooms: RoomsDep) -> list[dict]:
    return await rooms.list_for_user(auth.user["id"])


@router.post("", status_code=201, response_model=RoomSummary)
async def create_room(body: CreateRoomRequest, auth: AuthDep, rooms: RoomsDep) -> dict:
    room = await rooms.create(
        owner_id=auth.user["id"], name=body.name, wrapped_key=body.wrapped_key.model_dump()
    )
    return {**room, "member_count": 1}


@router.get("/{room_id}", response_model=RoomDetail)
async def get_room(
    room_id: UUID,
    auth: AuthDep,
    rooms: RoomsDep,
    users: UsersDep,
    manager: ConnectionManagerDep,
) -> dict:
    room = await _require_member(rooms, room_id, auth.user["id"])
    members = [await users.get(member_id) for member_id in await rooms.member_ids(str(room_id))]
    members = sorted((member for member in members if member), key=lambda member: member["username"])
    wrapped_key = await rooms.get_wrapped_key(str(room_id), auth.user["id"])
    return {
        **room,
        "members": members,
        "roles": await rooms.get_roles(str(room_id)),
        "wrapped_key": wrapped_key,
        "avatars": await rooms.get_avatars(str(room_id)),
        "online": {member["id"]: manager.is_online(member["id"]) for member in members},
    }


@router.post("/{room_id}/members", status_code=201, response_model=UserPublic)
async def add_member(
    room_id: UUID, body: AddMemberRequest, auth: AuthDep, rooms: RoomsDep, users: UsersDep, bus: EventBusDep
) -> dict:
    """Ajoute un membre. Le client de l'invitant fournit la clé du salon enveloppée pour lui.

    Réservé au chef et aux sous-chefs du salon.
    """
    room = await _require_member(rooms, room_id, auth.user["id"])
    if not await _can_manage_members(rooms, room, auth.user["id"]):
        raise HTTPException(status_code=403, detail="Seul le chef ou un sous-chef peut ajouter des membres")

    new_member = await users.get_by_username(body.username)
    if new_member is None:
        raise HTTPException(status_code=404, detail="Utilisateur introuvable")
    added = await rooms.add_member(
        room_id=str(room_id), user_id=new_member["id"], wrapped_key=body.wrapped_key.model_dump()
    )
    if not added:
        raise HTTPException(status_code=409, detail="Déjà membre du salon")

    await bus.publish(
        {
            "type": "member_added",
            "room_id": str(room_id),
            "user": {
                "id": new_member["id"],
                "username": new_member["username"],
                "public_key": new_member["public_key"],
                "display_name": new_member["display_name"],
                "bio": new_member["bio"],
            },
        },
        await rooms.member_ids(str(room_id)),
    )
    return new_member


@router.post("/{room_id}/roles", status_code=204)
async def set_role(
    room_id: UUID,
    body: SetRoleRequest,
    auth: AuthDep,
    rooms: RoomsDep,
    users: UsersDep,
    bus: EventBusDep,
) -> None:
    """Nomme un sous-chef ou rétrograde un membre. Seul le chef du salon peut le faire."""
    room = await _require_member(rooms, room_id, auth.user["id"])
    if room["owner_id"] != auth.user["id"]:
        raise HTTPException(status_code=403, detail="Seul le chef du salon peut changer les grades")

    target = await users.get_by_username(body.username)
    if target is None:
        raise HTTPException(status_code=404, detail="Utilisateur introuvable")
    if target["id"] == auth.user["id"]:
        raise HTTPException(status_code=400, detail="Vous ne pouvez pas changer votre propre grade")
    if not await rooms.is_member(str(room_id), target["id"]):
        raise HTTPException(status_code=404, detail="Salon introuvable")

    await rooms.set_role(str(room_id), target["id"], body.role)
    await bus.publish(
        {
            "type": "role_changed",
            "room_id": str(room_id),
            "user": {
                "id": target["id"],
                "username": target["username"],
                "public_key": target["public_key"],
                "display_name": target["display_name"],
                "bio": target["bio"],
            },
            "role": body.role,
        },
        await rooms.member_ids(str(room_id)),
    )


@router.put("/{room_id}/avatar", status_code=204)
async def set_avatar(
    room_id: UUID,
    body: AvatarRequest,
    auth: AuthDep,
    rooms: RoomsDep,
    messages: MessagesDep,
) -> None:
    """Enregistre l'avatar chiffré de l'utilisateur courant dans ce salon."""
    await _require_member(rooms, room_id, auth.user["id"])
    if not await messages.reserve_iv(str(room_id), body.iv):
        raise HTTPException(status_code=409, detail="IV déjà utilisé dans ce salon")
    await rooms.set_avatar(str(room_id), auth.user["id"], {"iv": body.iv, "ciphertext": body.ciphertext})
