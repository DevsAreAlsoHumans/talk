"""Endpoint WebSocket ``/ws`` — temps réel authentifié.

Sécurité :
- le cookie de session est vérifié avant tout (rejet code 4401 sinon) ;
- l'origine (Origin) doit correspondre à l'hôte de la requête (rejet sinon) ;
- le client s'abonne/se désabonne de salons via des messages JSON et les
  événements ``new_message`` / ``member_joined`` / ``room_key`` sont diffusés
  aux abonnés (server push only — le récepteur répond via REST).
"""

from __future__ import annotations

import json

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from app.realtime.hub import InProcessHub
from app.security.csrf import origin_matches_host
from app.security.sessions import get_session

router = APIRouter()


async def _handle_message(websocket: WebSocket, hub: InProcessHub, data: object) -> None:
    """Traite un message JSON entrant du client."""
    if not isinstance(data, dict):
        return
    msg_type = data.get("type")

    if msg_type in {"subscribe", "unsubscribe"}:
        room_ids = data.get("room_ids") or []
        for room_id in room_ids if isinstance(room_ids, list) else []:
            if not isinstance(room_id, str):
                continue
            if msg_type == "subscribe":
                hub.subscribe(room_id, websocket)
            else:
                hub.unsubscribe(room_id, websocket)
        return

    if msg_type in {"new_message", "member_joined", "room_key"}:
        payload = data.get("payload")
        if not isinstance(payload, dict):
            return
        room_id = payload.get("room_id")
        if isinstance(room_id, str):
            # Re-diffusion aux abonnés du salon (le récepteur appelle ensuite REST).
            await hub.publish(room_id, {"type": msg_type, "payload": payload})


@router.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket) -> None:
    """Connexion WebSocket : authentifiée par cookie, abonnements par salon."""
    redis = websocket.app.state.redis
    hub: InProcessHub = websocket.app.state.hub

    # 1. Authentification — le cookie de session doit être valide.
    if get_session(redis, websocket) is None:
        await websocket.close(code=4401)
        return

    # 2. Vérification d'origine (anti cross-site WebSocket hijacking).
    if not origin_matches_host(websocket):
        await websocket.close(code=1008)
        return

    await websocket.accept()
    try:
        while True:
            message = await websocket.receive_json()
            await _handle_message(websocket, hub, message)
    except (WebSocketDisconnect, json.JSONDecodeError):
        pass
    finally:
        hub.disconnect(websocket)
