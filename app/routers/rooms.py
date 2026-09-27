from datetime import datetime
import secrets

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from redis.asyncio import Redis

from app.database import get_redis
from app.models import MemberAdd, Room, RoomCreate, RoomType
from app.security import SecurityUtils
from app.services.redis_store import encode, get_json, set_json

router = APIRouter(prefix="/api/rooms", tags=["rooms"])
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/login")

ROOM_KEY = "room:{}"
MEMBERS_KEY = "room:{}:members"
USER_KEY = "user:{}"
USER_EMAIL_KEY = "user:email:{}"
USER_NAME_KEY = "user:username:{}"
TYPE_KEY = "rooms:{}"
CHANNELS_KEY = "server:{}:channels"
MESSAGE_IDS_KEY = "room:{}:messages"
HIDDEN_DIRECTS_KEY = "user:{}:hidden_directs"


async def get_current_user_id(token: str = Depends(oauth2_scheme)) -> str:
    return SecurityUtils.extract_user_id_from_token(token)


async def get_user_by_identifier(redis: Redis, identifier: str) -> dict:
    normalized = identifier.strip().lower()
    user_id = await redis.get(USER_EMAIL_KEY.format(normalized))
    if user_id is None:
        user_id = await redis.get(USER_NAME_KEY.format(normalized))
    user = await get_json(redis, USER_KEY.format(user_id)) if user_id else None
    if not user:
        raise HTTPException(status_code=404, detail="Utilisateur introuvable")
    return user


async def require_room(redis: Redis, room_id: str) -> dict:
    room = await get_json(redis, ROOM_KEY.format(room_id))
    if not room:
        raise HTTPException(status_code=404, detail="Salon introuvable")
    return room


async def require_member(redis: Redis, room_id: str, user_id: str) -> dict:
    room = await require_room(redis, room_id)
    member_room_id = room_id
    if room["room_type"] == RoomType.CHANNEL.value:
        member_room_id = room["parent_server"]
    if not await redis.sismember(MEMBERS_KEY.format(member_room_id), user_id):
        raise HTTPException(status_code=403, detail="Vous n'êtes pas membre de cet espace")
    return room


async def add_member(redis: Redis, room_id: str, user_id: str) -> bool:
    added = await redis.sadd(MEMBERS_KEY.format(room_id), user_id)
    if added:
        room = await require_room(redis, room_id)
        room["member_count"] = room.get("member_count", 0) + 1
        await set_json(redis, ROOM_KEY.format(room_id), room)
    return bool(added)


async def rooms_from_index(redis: Redis, index: str, user_id: str) -> list[dict]:
    room_ids = await redis.smembers(index)
    rooms = []
    for room_id in room_ids:
        if await redis.sismember(MEMBERS_KEY.format(room_id), user_id):
            room = await get_json(redis, ROOM_KEY.format(room_id))
            if room and not (room["room_type"] == RoomType.DIRECT.value and await redis.sismember(HIDDEN_DIRECTS_KEY.format(user_id), room_id)):
                rooms.append(room)
    return rooms


@router.get("/", response_model=list[Room])
async def list_servers(token: str = Depends(oauth2_scheme), redis: Redis = Depends(get_redis)):
    return await rooms_from_index(redis, TYPE_KEY.format("server"), await get_current_user_id(token))


@router.get("/servers", response_model=list[Room])
async def list_servers_explicit(token: str = Depends(oauth2_scheme), redis: Redis = Depends(get_redis)):
    return await rooms_from_index(redis, TYPE_KEY.format("server"), await get_current_user_id(token))


@router.get("/server/{server_id}/channels", response_model=list[Room])
async def list_server_channels(server_id: str, token: str = Depends(oauth2_scheme), redis: Redis = Depends(get_redis)):
    user_id = await get_current_user_id(token)
    server = await require_member(redis, server_id, user_id)
    if server["room_type"] != RoomType.SERVER.value:
        raise HTTPException(status_code=400, detail="La cible n'est pas un serveur")
    channel_ids = await redis.smembers(CHANNELS_KEY.format(server_id))
    channels = [await get_json(redis, ROOM_KEY.format(room_id)) for room_id in channel_ids]
    return [channel for channel in channels if channel]


@router.get("/groups", response_model=list[Room])
async def list_groups(token: str = Depends(oauth2_scheme), redis: Redis = Depends(get_redis)):
    return await rooms_from_index(redis, TYPE_KEY.format("group"), await get_current_user_id(token))


@router.get("/directs", response_model=list[Room])
async def list_directs(token: str = Depends(oauth2_scheme), redis: Redis = Depends(get_redis)):
    return await rooms_from_index(redis, TYPE_KEY.format("direct"), await get_current_user_id(token))


@router.get("/{room_id}", response_model=Room)
async def get_room(room_id: str, token: str = Depends(oauth2_scheme), redis: Redis = Depends(get_redis)):
    return await require_member(redis, room_id, await get_current_user_id(token))


@router.post("/", response_model=Room, status_code=status.HTTP_201_CREATED)
async def create_room(room_data: RoomCreate, token: str = Depends(oauth2_scheme), redis: Redis = Depends(get_redis)):
    user_id = await get_current_user_id(token)
    if room_data.room_type == RoomType.CHANNEL:
        parent = await require_member(redis, room_data.parent_server, user_id)
        if parent["room_type"] != RoomType.SERVER.value:
            raise HTTPException(status_code=400, detail="Un salon doit appartenir à un serveur")
        if parent["created_by"] != user_id:
            raise HTTPException(status_code=403, detail="Seul le propriétaire peut créer un salon")
    member_ids = set(room_data.member_ids)
    for identifier in room_data.member_identifiers:
        member_ids.add((await get_user_by_identifier(redis, identifier))["id"])
    for member_id in member_ids:
        if not await redis.exists(USER_KEY.format(member_id)):
            raise HTTPException(status_code=404, detail="Un membre invité est introuvable")
    if room_data.room_type == RoomType.DIRECT:
        target_ids = member_ids | {user_id}
        for existing_id in await redis.smembers(TYPE_KEY.format(RoomType.DIRECT.value)):
            existing = await get_json(redis, ROOM_KEY.format(existing_id))
            existing_members = await redis.smembers(MEMBERS_KEY.format(existing_id))
            if existing and existing_members == target_ids:
                async with redis.pipeline(transaction=True) as pipeline:
                    pipeline.srem(HIDDEN_DIRECTS_KEY.format(user_id), existing_id)
                    for member_id in target_ids:
                        pipeline.srem(HIDDEN_DIRECTS_KEY.format(member_id), existing_id)
                    await pipeline.execute()
                return existing
    room_id = f"room_{secrets.token_urlsafe(8)}"
    members = member_ids | {user_id}
    room = {
        "id": room_id,
        "name": room_data.name,
        "description": room_data.description,
        "room_type": room_data.room_type.value,
        "is_private": room_data.is_private or room_data.room_type in (RoomType.GROUP, RoomType.DIRECT),
        "parent_server": room_data.parent_server,
        "created_by": user_id,
        "created_at": datetime.utcnow().isoformat(),
        "member_count": len(members),
    }
    async with redis.pipeline(transaction=True) as pipeline:
        pipeline.set(ROOM_KEY.format(room_id), encode(room))
        pipeline.sadd(MEMBERS_KEY.format(room_id), *members)
        pipeline.sadd(TYPE_KEY.format(room["room_type"]), room_id)
        if room["room_type"] == RoomType.CHANNEL.value:
            pipeline.sadd(CHANNELS_KEY.format(room_data.parent_server), room_id)
        await pipeline.execute()
    return room


@router.put("/{room_id}", response_model=Room)
async def update_room(room_id: str, room_data: RoomCreate, token: str = Depends(oauth2_scheme), redis: Redis = Depends(get_redis)):
    user_id = await get_current_user_id(token)
    room = await require_member(redis, room_id, user_id)
    if room["created_by"] != user_id:
        raise HTTPException(status_code=403, detail="Non autorisé")
    if room["room_type"] != room_data.room_type.value:
        raise HTTPException(status_code=400, detail="Le type d'espace ne peut pas être modifié")
    if room["room_type"] == RoomType.CHANNEL.value and room["parent_server"] != room_data.parent_server:
        raise HTTPException(status_code=400, detail="Le serveur parent ne peut pas être modifié")
    room.update({"name": room_data.name, "description": room_data.description, "is_private": room_data.is_private})
    await set_json(redis, ROOM_KEY.format(room_id), room)
    return room


@router.delete("/{room_id}")
async def delete_room(room_id: str, token: str = Depends(oauth2_scheme), redis: Redis = Depends(get_redis)):
    user_id = await get_current_user_id(token)
    room = await require_member(redis, room_id, user_id)
    if room["room_type"] == RoomType.DIRECT.value:
        await redis.sadd(HIDDEN_DIRECTS_KEY.format(user_id), room_id)
        return {"message": "Conversation supprimée de votre liste"}
    if room["created_by"] != user_id:
        raise HTTPException(status_code=403, detail="Non autorisé")
    message_ids = await redis.zrange(MESSAGE_IDS_KEY.format(room_id), 0, -1)
    async with redis.pipeline(transaction=True) as pipeline:
        pipeline.delete(ROOM_KEY.format(room_id), MEMBERS_KEY.format(room_id), MESSAGE_IDS_KEY.format(room_id))
        pipeline.srem(TYPE_KEY.format(room["room_type"]), room_id)
        if room["room_type"] == RoomType.CHANNEL.value:
            pipeline.srem(CHANNELS_KEY.format(room["parent_server"]), room_id)
        for message_id in message_ids:
            pipeline.delete(f"message:{message_id}")
        await pipeline.execute()
    return {"message": "Espace supprimé"}


@router.post("/{room_id}/members")
async def add_room_member(room_id: str, member_data: MemberAdd, token: str = Depends(oauth2_scheme), redis: Redis = Depends(get_redis)):
    user_id = await get_current_user_id(token)
    room = await require_member(redis, room_id, user_id)
    if room["room_type"] == RoomType.DIRECT.value:
        raise HTTPException(status_code=400, detail="Un message direct ne peut pas recevoir de membre")
    if room["created_by"] != user_id:
        raise HTTPException(status_code=403, detail="Seul le créateur peut ajouter un membre")
    member = await get_user_by_identifier(redis, member_data.identifier)
    target_room_id = room["parent_server"] if room["room_type"] == RoomType.CHANNEL.value else room_id
    added = await add_member(redis, target_room_id, member["id"])
    return {"message": "Membre ajouté" if added else "Membre déjà présent", "user_id": member["id"]}


@router.get("/{room_id}/members")
async def list_room_members(room_id: str, token: str = Depends(oauth2_scheme), redis: Redis = Depends(get_redis)):
    await require_member(redis, room_id, await get_current_user_id(token))
    room = await require_room(redis, room_id)
    member_room_id = room["parent_server"] if room["room_type"] == RoomType.CHANNEL.value else room_id
    members = []
    for user_id in await redis.smembers(MEMBERS_KEY.format(member_room_id)):
        user = await get_json(redis, USER_KEY.format(user_id))
        if user:
            members.append({"id": user["id"], "username": user["username"], "email": user["email"]})
    return members


@router.delete("/{room_id}/members/{member_id}")
async def remove_room_member(room_id: str, member_id: str, token: str = Depends(oauth2_scheme), redis: Redis = Depends(get_redis)):
    user_id = await get_current_user_id(token)
    room = await require_member(redis, room_id, user_id)
    if room["room_type"] == RoomType.DIRECT.value:
        raise HTTPException(status_code=400, detail="Un message direct ne gère pas de membres")
    if room["created_by"] != user_id:
        raise HTTPException(status_code=403, detail="Seul le propriétaire peut supprimer un membre")
    if member_id == room["created_by"]:
        raise HTTPException(status_code=400, detail="Le propriétaire ne peut pas être supprimé")
    target_room_id = room["parent_server"] if room["room_type"] == RoomType.CHANNEL.value else room_id
    removed = await redis.srem(MEMBERS_KEY.format(target_room_id), member_id)
    if not removed:
        raise HTTPException(status_code=404, detail="Membre introuvable dans cet espace")
    target_room = await require_room(redis, target_room_id)
    target_room["member_count"] = max(0, target_room.get("member_count", 1) - 1)
    await set_json(redis, ROOM_KEY.format(target_room_id), target_room)
    return {"message": "Membre supprimé", "user_id": member_id}


@router.post("/{room_id}/join")
async def join_room(room_id: str, token: str = Depends(oauth2_scheme), redis: Redis = Depends(get_redis)):
    user_id = await get_current_user_id(token)
    room = await require_room(redis, room_id)
    if room["room_type"] in (RoomType.CHANNEL.value, RoomType.DIRECT.value):
        raise HTTPException(status_code=400, detail="Rejoignez le serveur ou utilisez l'invitation prévue")
    await add_member(redis, room_id, user_id)
    return {"message": "Espace rejoint", "room_id": room_id}
