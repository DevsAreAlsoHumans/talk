from bson import ObjectId
from bson.errors import InvalidId
from fastapi import APIRouter, Cookie, WebSocket, WebSocketDisconnect, status

from app.db.mongo import db
from app.db.redis_client import redis_client
from app.security.sessions import SESSION_COOKIE_NAME, get_session
from app.services.realtime import room_channel

router = APIRouter()


@router.websocket("/ws/rooms/{room_id}")
async def room_websocket(
    websocket: WebSocket,
    room_id: str,
    session_id: str | None = Cookie(default=None, alias=SESSION_COOKIE_NAME),
) -> None:
    """Relaie en temps réel (via Redis pub/sub) les messages d'un salon à ses membres connectés."""
    session = await get_session(session_id) if session_id else None
    if session is None:
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        return

    try:
        object_id = ObjectId(room_id)
    except InvalidId:
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        return

    room = await db.rooms.find_one({"_id": object_id})
    if room is None or session["user_id"] not in room["member_ids"]:
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        return

    await websocket.accept()
    pubsub = redis_client.pubsub()
    channel = room_channel(room_id)
    await pubsub.subscribe(channel)
    try:
        async for message in pubsub.listen():
            if message["type"] != "message":
                continue
            await websocket.send_text(message["data"])
    except WebSocketDisconnect:
        pass
    finally:
        await pubsub.unsubscribe(channel)
        await pubsub.aclose()
