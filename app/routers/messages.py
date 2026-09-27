from datetime import datetime
import secrets

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from redis.asyncio import Redis

from app.database import get_redis
from app.models import Message, MessageCreate
from app.security import SecurityUtils
from app.services.redis_store import encode, get_json

router = APIRouter(prefix="/api/messages", tags=["messages"])
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/login")

ROOM_KEY = "room:{}"
MEMBERS_KEY = "room:{}:members"
MESSAGE_KEY = "message:{}"
MESSAGE_IDS_KEY = "room:{}:messages"


async def get_current_user_id(token: str = Depends(oauth2_scheme)) -> str:
    return SecurityUtils.extract_user_id_from_token(token)


async def require_member(redis: Redis, room_id: str, user_id: str) -> None:
    if not await redis.exists(ROOM_KEY.format(room_id)):
        raise HTTPException(status_code=404, detail="Salon non trouvé")
    if not await redis.sismember(MEMBERS_KEY.format(room_id), user_id):
        raise HTTPException(status_code=403, detail="Vous n'êtes pas membre de ce salon")


@router.get("/room/{room_id}", response_model=list[Message])
async def list_messages(room_id: str, token: str = Depends(oauth2_scheme), redis: Redis = Depends(get_redis)):
    user_id = await get_current_user_id(token)
    await require_member(redis, room_id, user_id)
    message_ids = await redis.zrange(MESSAGE_IDS_KEY.format(room_id), 0, -1)
    messages = [await get_json(redis, MESSAGE_KEY.format(message_id)) for message_id in message_ids]
    return [message for message in messages if message]


@router.post("/", response_model=Message, status_code=status.HTTP_201_CREATED)
async def send_message(message_data: MessageCreate, token: str = Depends(oauth2_scheme), redis: Redis = Depends(get_redis)):
    user_id = await get_current_user_id(token)
    await require_member(redis, message_data.room_id, user_id)
    message_id = f"msg_{secrets.token_urlsafe(8)}"
    created_at = datetime.utcnow()
    message = {
        "id": message_id,
        "room_id": message_data.room_id,
        "user_id": user_id,
        "content": message_data.content,
        "message_type": message_data.message_type,
        "parent_message_id": message_data.parent_message_id,
        "encrypted": message_data.encrypted,
        "created_at": created_at.isoformat(),
    }
    async with redis.pipeline(transaction=True) as pipeline:
        pipeline.set(MESSAGE_KEY.format(message_id), encode(message))
        pipeline.zadd(MESSAGE_IDS_KEY.format(message_data.room_id), {message_id: created_at.timestamp()})
        pipeline.publish(f"room:{message_data.room_id}:events", encode({"type": "message", **message}))
        await pipeline.execute()
    return message


@router.get("/{message_id}", response_model=Message)
async def get_message(message_id: str, token: str = Depends(oauth2_scheme), redis: Redis = Depends(get_redis)):
    user_id = await get_current_user_id(token)
    message = await get_json(redis, MESSAGE_KEY.format(message_id))
    if not message:
        raise HTTPException(status_code=404, detail="Message non trouvé")
    await require_member(redis, message["room_id"], user_id)
    return message


@router.delete("/{message_id}")
async def delete_message(message_id: str, token: str = Depends(oauth2_scheme), redis: Redis = Depends(get_redis)):
    user_id = await get_current_user_id(token)
    message = await get_json(redis, MESSAGE_KEY.format(message_id))
    if not message:
        raise HTTPException(status_code=404, detail="Message non trouvé")
    await require_member(redis, message["room_id"], user_id)
    if message["user_id"] != user_id:
        raise HTTPException(status_code=403, detail="Non autorisé")
    async with redis.pipeline(transaction=True) as pipeline:
        pipeline.delete(MESSAGE_KEY.format(message_id))
        pipeline.zrem(MESSAGE_IDS_KEY.format(message["room_id"]), message_id)
        await pipeline.execute()
    return {"message": "Message supprimé"}
