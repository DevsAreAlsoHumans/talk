import asyncio
from datetime import datetime
import json
import secrets

from fastapi import APIRouter, Depends, WebSocket, WebSocketDisconnect
from fastapi.security import OAuth2PasswordBearer
from redis.asyncio import Redis

from app.database import get_redis
from app.security import SecurityUtils
from app.services.redis_store import encode

router = APIRouter(prefix="/ws", tags=["websocket"])
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/login")


@router.websocket("/")
async def websocket_endpoint(websocket: WebSocket, token: str, redis: Redis = Depends(get_redis)):
    user_id = SecurityUtils.extract_user_id_from_token(token)
    await websocket.accept()
    pubsub = redis.pubsub()
    subscribed_channel = None
    listener_task = None

    async def listen_to_room() -> None:
        while True:
            event = await pubsub.get_message(ignore_subscribe_messages=True, timeout=1.0)
            if event and event.get("data"):
                await websocket.send_text(event["data"])
            await asyncio.sleep(0.05)

    try:
        while True:
            data = json.loads(await websocket.receive_text())
            action = data.get("action")
            room_id = data.get("room_id")

            if action == "join_room" and room_id:
                if subscribed_channel:
                    await pubsub.unsubscribe(subscribed_channel)
                subscribed_channel = f"room:{room_id}:events"
                await pubsub.subscribe(subscribed_channel)
                if listener_task is None:
                    listener_task = asyncio.create_task(listen_to_room())
                await websocket.send_json({"type": "joined_room", "room_id": room_id})

            elif action == "send_message" and room_id:
                event = {
                    "type": "message",
                    "room_id": room_id,
                    "user_id": user_id,
                    "content": data.get("content", ""),
                    "encrypted": data.get("encrypted", True),
                    "timestamp": datetime.utcnow().isoformat(),
                    "id": f"ws_{secrets.token_urlsafe(8)}",
                }
                await redis.publish(f"room:{room_id}:events", encode(event))

            elif action == "ping":
                await websocket.send_json({"type": "pong"})
    except WebSocketDisconnect:
        pass
    finally:
        if listener_task:
            listener_task.cancel()
        if subscribed_channel:
            await pubsub.unsubscribe(subscribed_channel)
        await pubsub.close()


@router.get("/connections")
async def get_connections():
    return {"message": "Les connexions sont gérées par Redis Pub/Sub"}
