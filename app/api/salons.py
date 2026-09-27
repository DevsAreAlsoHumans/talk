"""Routes des salons et des canaux."""

from fastapi import APIRouter, Depends, HTTPException, status
from redis import Redis

from app.api.deps import (
    channel_access,
    current_user,
    require_csrf,
    salon_moderator,
    salon_owner,
    salon_role,
)
from app.db import get_redis
from app.repositories import salons, users
from app.schemas import (
    ChannelCreate,
    ChannelPublic,
    ChannelUpdate,
    MemberAdd,
    MemberList,
    MemberPublic,
    MessageResponse,
    SalonCreate,
    SalonPublic,
    SalonUpdate,
)

router = APIRouter(tags=["salons"])


@router.post(
    "/salons",
    response_model=SalonPublic,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require_csrf)],
)
def create_salon(
    payload: SalonCreate,
    redis: Redis = Depends(get_redis),
    user: dict = Depends(current_user),
) -> SalonPublic:
    salon = salons.create_salon(redis, payload.name, user["id"])
    salon["role"] = salons.ROLE_OWNER
    salon["member_count"] = 1
    return SalonPublic(**salon)


@router.get("/salons", response_model=list[SalonPublic])
def list_salons(
    redis: Redis = Depends(get_redis),
    user: dict = Depends(current_user),
) -> list[SalonPublic]:
    return [SalonPublic(**salon) for salon in salons.list_salons(redis, user["id"])]


@router.get("/salons/{salon_id}", response_model=SalonPublic)
def get_salon(
    salon_id: str,
    redis: Redis = Depends(get_redis),
    role: str = Depends(salon_role),
) -> SalonPublic:
    salon = salons.get_salon(redis, salon_id)
    if salon is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Salon introuvable.")
    salon["role"] = role
    salon["member_count"] = salons.member_count(redis, salon_id)
    return SalonPublic(**salon)


@router.patch(
    "/salons/{salon_id}",
    response_model=SalonPublic,
    dependencies=[Depends(require_csrf)],
)
def rename_salon(
    salon_id: str,
    payload: SalonUpdate,
    redis: Redis = Depends(get_redis),
    _role: str = Depends(salon_moderator),
) -> SalonPublic:
    salons.rename_salon(redis, salon_id, payload.name)
    salon = salons.get_salon(redis, salon_id) or {}
    salon["role"] = _role
    salon["member_count"] = salons.member_count(redis, salon_id)
    return SalonPublic(**salon)


@router.delete(
    "/salons/{salon_id}",
    response_model=MessageResponse,
    dependencies=[Depends(require_csrf)],
)
def delete_salon(
    salon_id: str,
    redis: Redis = Depends(get_redis),
    _role: str = Depends(salon_owner),
) -> MessageResponse:
    salons.delete_salon(redis, salon_id)
    return MessageResponse(detail="Salon supprime.")


# --- Appartenance ---------------------------------------------------------


@router.get("/salons/{salon_id}/members", response_model=MemberList)
def list_members(
    salon_id: str,
    redis: Redis = Depends(get_redis),
    _role: str = Depends(salon_role),
) -> MemberList:
    members = []
    for user_id in salons.list_member_ids(redis, salon_id):
        user = users.get_by_id(redis, user_id)
        if user is None:
            continue
        members.append(
            MemberPublic(
                id=user["id"],
                username=user["username"],
                role=salons.get_role(redis, salon_id, user_id) or salons.ROLE_MEMBER,
            )
        )
    return MemberList(members=members)


@router.post(
    "/salons/{salon_id}/members",
    response_model=MessageResponse,
    dependencies=[Depends(require_csrf)],
)
def add_member(
    salon_id: str,
    payload: MemberAdd,
    redis: Redis = Depends(get_redis),
    actor: dict = Depends(current_user),
    role: str = Depends(salon_moderator),
) -> MessageResponse:
    target = users.get_by_username(redis, payload.username)
    if target is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Utilisateur introuvable."
        )
    if salons.get_role(redis, salon_id, target["id"]) is not None:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Deja membre du salon.")
    granted = salons.ROLE_MODERATOR if role == salons.ROLE_OWNER else salons.ROLE_MEMBER
    salons.set_role(redis, salon_id, target["id"], granted)
    return MessageResponse(detail=f"{target['username']} a ete ajoute.")


@router.delete(
    "/salons/{salon_id}/members/{user_id}",
    response_model=MessageResponse,
    dependencies=[Depends(require_csrf)],
)
def remove_member(
    salon_id: str,
    user_id: str,
    redis: Redis = Depends(get_redis),
    actor: dict = Depends(current_user),
    role: str = Depends(salon_moderator),
) -> MessageResponse:
    if salons.get_role(redis, salon_id, user_id) is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Membre introuvable.")
    if user_id == actor["id"] and role != salons.ROLE_OWNER:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Seul le proprietaire peut se retirer lui-meme.",
        )
    salon = salons.get_salon(redis, salon_id) or {}
    if user_id == salon.get("owner_id"):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Le proprietaire ne peut pas etre retire.",
        )
    salons.remove_member(redis, salon_id, user_id)
    return MessageResponse(detail="Membre retire.")


# --- Canaux ---------------------------------------------------------------


@router.post(
    "/salons/{salon_id}/channels",
    response_model=ChannelPublic,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require_csrf)],
)
def create_channel(
    salon_id: str,
    payload: ChannelCreate,
    redis: Redis = Depends(get_redis),
    user: dict = Depends(current_user),
    _role: str = Depends(salon_moderator),
) -> ChannelPublic:
    names = {item["name"] for item in salons.list_channels(redis, salon_id)}
    if payload.name in names:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT, detail="Nom de canal deja utilise."
        )
    channel = salons.create_channel(
        redis, salon_id, payload.name, topic=payload.topic, kind=payload.kind
    )
    if payload.kind == salons.KIND_PRIVATE:
        salons.add_channel_member(redis, channel["id"], user["id"])
    return ChannelPublic(**channel)


@router.get("/salons/{salon_id}/channels", response_model=list[ChannelPublic])
def list_channels(
    salon_id: str,
    redis: Redis = Depends(get_redis),
    user: dict = Depends(current_user),
    _role: str = Depends(salon_role),
) -> list[ChannelPublic]:
    visible = []
    for channel in salons.list_channels(redis, salon_id):
        if salons.can_access_channel(redis, channel["id"], user["id"]) is not None:
            visible.append(ChannelPublic(**channel))
    return visible


@router.get("/channels/{channel_id}", response_model=ChannelPublic)
def get_channel(channel: dict = Depends(channel_access)) -> ChannelPublic:
    return ChannelPublic(**channel)


@router.patch(
    "/channels/{channel_id}",
    response_model=ChannelPublic,
    dependencies=[Depends(require_csrf)],
)
def update_channel(
    channel_id: str,
    payload: ChannelUpdate,
    redis: Redis = Depends(get_redis),
    user: dict = Depends(current_user),
    role: str = Depends(salon_role),
) -> ChannelPublic:
    if salons.ROLE_RANK[role] < salons.ROLE_RANK[salons.ROLE_MODERATOR]:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Droits insuffisants.")
    fields = payload.model_dump(exclude_none=True)
    if not fields:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Aucune modification fournie.",
        )
    if "name" in fields:
        others = {
            item["name"]
            for item in salons.list_channels(redis, channel["salon_id"])
            if item["id"] != channel_id
        }
        if fields["name"] in others:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT, detail="Nom de canal deja utilise."
            )
    salons.update_channel(redis, channel_id, fields)
    return ChannelPublic(**(salons.get_channel(redis, channel_id) or {}))


@router.delete(
    "/channels/{channel_id}",
    response_model=MessageResponse,
    dependencies=[Depends(require_csrf)],
)
def delete_channel(
    channel: dict = Depends(channel_access),
    redis: Redis = Depends(get_redis),
    user: dict = Depends(current_user),
    role: str = Depends(salon_role),
) -> MessageResponse:
    if salons.ROLE_RANK[role] < salons.ROLE_RANK[salons.ROLE_MODERATOR]:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Droits insuffisants.")
    if len(salons.list_channels(redis, channel["salon_id"])) <= 1:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Un salon doit conserver au moins un canal.",
        )
    salons.delete_channel(redis, channel["id"])
    return MessageResponse(detail="Canal supprime.")


@router.post(
    "/channels/{channel_id}/members",
    response_model=MessageResponse,
    dependencies=[Depends(require_csrf)],
)
def add_channel_member(
    payload: MemberAdd,
    channel: dict = Depends(channel_access),
    redis: Redis = Depends(get_redis),
    user: dict = Depends(current_user),
    role: str = Depends(salon_role),
) -> MessageResponse:
    if channel["kind"] != salons.KIND_PRIVATE:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Seuls les canaux prives ont une liste d'acces.",
        )
    if salons.ROLE_RANK[role] < salons.ROLE_RANK[salons.ROLE_MODERATOR]:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Droits insuffisants.")
    target = users.get_by_username(redis, payload.username)
    if target is None or salons.get_role(redis, channel["salon_id"], target["id"]) is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Membre du salon introuvable."
        )
    salons.add_channel_member(redis, channel["id"], target["id"])
    return MessageResponse(detail=f"{target['username']} a acces au canal.")


@router.delete(
    "/channels/{channel_id}/members/{user_id}",
    response_model=MessageResponse,
    dependencies=[Depends(require_csrf)],
)
def remove_channel_member(
    user_id: str,
    channel: dict = Depends(channel_access),
    redis: Redis = Depends(get_redis),
    user: dict = Depends(current_user),
    role: str = Depends(salon_role),
) -> MessageResponse:
    if salons.ROLE_RANK[role] < salons.ROLE_RANK[salons.ROLE_MODERATOR]:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Droits insuffisants.")
    if not salons.is_channel_member(redis, channel["id"], user_id):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Membre introuvable.")
    salons.remove_channel_member(redis, channel["id"], user_id)
    return MessageResponse(detail="Acces canal retire.")


@router.get("/channels/{channel_id}/members", response_model=MemberList)
def list_channel_members(
    channel: dict = Depends(channel_access),
    redis: Redis = Depends(get_redis),
    _role: str = Depends(salon_role),
) -> MemberList:
    members = []
    for user_id in salons.list_channel_member_ids(redis, channel["id"]):
        user = users.get_by_id(redis, user_id)
        if user is None:
            continue
        members.append(
            MemberPublic(
                id=user["id"],
                username=user["username"],
                role=salons.get_role(redis, channel["salon_id"], user_id) or salons.ROLE_MEMBER,
            )
        )
    return MemberList(members=members)
