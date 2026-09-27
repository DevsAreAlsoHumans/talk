from datetime import datetime
import secrets

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from redis.asyncio import Redis

from app.database import get_redis
from app.models import Room, RoomCreate
from app.security import SecurityUtils
from app.services.redis_store import encode, get_json, set_json

router = APIRouter(prefix="/api/rooms", tags=["rooms"])
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/login")

ROOM_KEY = "room:{}"
PUBLIC_ROOMS_KEY = "rooms:public"
MEMBERS_KEY = "room:{}:members"


async def get_current_user_id(token: str = Depends(oauth2_scheme)) -> str:
    return SecurityUtils.extract_user_id_from_token(token)


async def require_member(redis: Redis, room_id: str, user_id: str) -> dict:
    room = await get_json(redis, ROOM_KEY.format(room_id))
    if not room:
        raise HTTPException(status_code=404, detail="Salon non trouvé")
    if not await redis.sismember(MEMBERS_KEY.format(room_id), user_id):
        raise HTTPException(status_code=403, detail="Vous n'êtes pas membre de ce salon")
    return room


@router.get("/", response_model=list[Room])
async def list_rooms(token: str = Depends(oauth2_scheme), redis: Redis = Depends(get_redis)):
    room_ids = await redis.smembers(PUBLIC_ROOMS_KEY)
    rooms = [await get_json(redis, ROOM_KEY.format(room_id)) for room_id in room_ids]
    return [room for room in rooms if room]


@router.get("/{room_id}", response_model=Room)
async def get_room(room_id: str, token: str = Depends(oauth2_scheme), redis: Redis = Depends(get_redis)):
    room = await get_json(redis, ROOM_KEY.format(room_id))
    if not room:
        raise HTTPException(status_code=404, detail="Salon non trouvé")
    return room


@router.post("/", response_model=Room, status_code=status.HTTP_201_CREATED)
async def create_room(room_data: RoomCreate, token: str = Depends(oauth2_scheme), redis: Redis = Depends(get_redis)):
    user_id = await get_current_user_id(token)
    room_id = f"room_{secrets.token_urlsafe(8)}"
    room = {
        "id": room_id,
        "name": room_data.name,
        "description": room_data.description,
        "room_type": room_data.room_type,
        "is_private": room_data.is_private,
        "parent_server": room_data.parent_server,
        "created_by": user_id,
        "created_at": datetime.utcnow().isoformat(),
        "member_count": 1,
    }
    async with redis.pipeline(transaction=True) as pipeline:
        pipeline.set(ROOM_KEY.format(room_id), encode(room))
        pipeline.sadd(MEMBERS_KEY.format(room_id), user_id)
        if not room_data.is_private:
            pipeline.sadd(PUBLIC_ROOMS_KEY, room_id)
        await pipeline.execute()
    return room


@router.put("/{room_id}", response_model=Room)
async def update_room(room_id: str, room_data: RoomCreate, token: str = Depends(oauth2_scheme), redis: Redis = Depends(get_redis)):
    user_id = await get_current_user_id(token)
    room = await require_member(redis, room_id, user_id)
    if room["created_by"] != user_id:
        raise HTTPException(status_code=403, detail="Non autorisé")
    room.update({
        "name": room_data.name,
        "description": room_data.description,
        "room_type": room_data.room_type,
        "is_private": room_data.is_private,
        "parent_server": room_data.parent_server,
    })
    await set_json(redis, ROOM_KEY.format(room_id), room)
    if room_data.is_private:
        await redis.srem(PUBLIC_ROOMS_KEY, room_id)
    else:
        await redis.sadd(PUBLIC_ROOMS_KEY, room_id)
    return room


@router.delete("/{room_id}")
async def delete_room(room_id: str, token: str = Depends(oauth2_scheme), redis: Redis = Depends(get_redis)):
    user_id = await get_current_user_id(token)
    room = await require_member(redis, room_id, user_id)
    if room["created_by"] != user_id:
        raise HTTPException(status_code=403, detail="Non autorisé")
    message_ids = await redis.zrange(f"room:{room_id}:messages", 0, -1)
    async with redis.pipeline(transaction=True) as pipeline:
        pipeline.delete(ROOM_KEY.format(room_id), MEMBERS_KEY.format(room_id), f"room:{room_id}:messages")
        pipeline.srem(PUBLIC_ROOMS_KEY, room_id)
        for message_id in message_ids:
            pipeline.delete(f"message:{message_id}")
        await pipeline.execute()
    return {"message": "Salon supprimé"}


@router.post("/{room_id}/join")
async def join_room(room_id: str, token: str = Depends(oauth2_scheme), redis: Redis = Depends(get_redis)):
    user_id = await get_current_user_id(token)
    room = await get_json(redis, ROOM_KEY.format(room_id))
    if not room:
        raise HTTPException(status_code=404, detail="Salon non trouvé")
    added = await redis.sadd(MEMBERS_KEY.format(room_id), user_id)
    if added:
        room["member_count"] = room.get("member_count", 1) + 1
        await set_json(redis, ROOM_KEY.format(room_id), room)
    return {"message": "Salon rejoint", "room_id": room_id}
