import json
import time
from typing import Any

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from app.realtime import ConnectionManager
from app.security import hash_token

router = APIRouter(tags=["temps réel"])


@router.websocket("/api/ws")
async def websocket_endpoint(websocket: WebSocket) -> None:
    settings = websocket.app.state.settings
    origin = websocket.headers.get("origin")
    if origin not in settings.origin_list:
        await websocket.close(code=1008, reason="Origine non autorisée")
        return

    token = websocket.cookies.get(settings.session_cookie_name)
    session_hash = hash_token(token) if token else ""
    session = None
    if token:
        session = await websocket.app.state.store.get_session(session_hash)
    if session is None:
        await websocket.close(code=4401, reason="Authentification requise")
        return
    user = await websocket.app.state.store.get_user(session["user_id"])
    if user is None:
        await websocket.close(code=4401, reason="Session invalide")
        return

    manager: ConnectionManager = websocket.app.state.manager
    await manager.connect(user["id"], websocket, session_hash)
    await websocket.send_json(
        {
            "type": "connection.ready",
            "server_time": int(time.time() * 1000),
        }
    )
    try:
        while True:
            raw_message = await websocket.receive_text()
            current_session = await websocket.app.state.store.get_session(session_hash)
            if current_session is None or current_session["user_id"] != user["id"]:
                await websocket.close(code=4401, reason="Session expirée")
                return
            if len(raw_message) > 2048:
                await websocket.send_json({"type": "error", "code": "payload_too_large"})
                await websocket.close(code=1009)
                return
            try:
                event = json.loads(raw_message)
            except json.JSONDecodeError:
                await websocket.send_json({"type": "error", "code": "invalid_json"})
                continue
            if not isinstance(event, dict):
                await websocket.send_json({"type": "error", "code": "invalid_event"})
                continue
            await _handle_event(websocket, event)
    except WebSocketDisconnect:
        pass
    finally:
        await manager.disconnect(user["id"], websocket)


async def _handle_event(websocket: WebSocket, event: dict[str, Any]) -> None:
    event_type = event.get("type")
    if event_type == "ping":
        await websocket.send_json({"type": "pong", "nonce": str(event.get("nonce", ""))[:128]})
    else:
        await websocket.send_json({"type": "error", "code": "unsupported_event"})
