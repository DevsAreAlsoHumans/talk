"""Endpoint WebSocket ``/ws`` — temps réel authentifié.

Sécurité :
- le cookie de session est vérifié avant tout (rejet code 4401 sinon) ;
- l'origine (Origin) doit correspondre à l'hôte de la requête (rejet sinon) ;
- un client ne peut s'abonner qu'aux salons dont il est membre (``rooms.is_member``) ;
- le serveur est **le seul émetteur** d'événements (``new_message``,
  ``member_joined``, ``room_key``, poussées par les endpoints REST) : les
  trames clients autres que ``subscribe``/``unsubscribe`` sont ignorées, ce qui
  interdit à un client d'injecter de faux événements.
"""

from __future__ import annotations

import json

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from app.realtime.hub import InProcessHub
from app.repositories import rooms
from app.security.csrf import origin_matches_host
from app.security.sessions import get_session

router = APIRouter()


async def _handle_message(
    websocket: WebSocket,
    hub: InProcessHub,
    data: object,
    *,
    redis,
    user_id: str | None,
) -> None:
    """Traite un message JSON entrant du client (subscriptions uniquement)."""
    if user_id is None or not isinstance(data, dict):
        return  # session anonyme : aucun abonnement possible
    msg_type = data.get("type")

    if msg_type in {"subscribe", "unsubscribe"}:
        room_ids = data.get("room_ids") or []
        for room_id in room_ids if isinstance(room_ids, list) else []:
            if not isinstance(room_id, str):
                continue
            if msg_type == "subscribe":
                # Un client ne s'abonne qu'aux salons dont il est membre.
                if rooms.is_member(redis, room_id, user_id):
                    hub.subscribe(room_id, websocket)
            else:
                hub.unsubscribe(room_id, websocket)


@router.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket) -> None:
    """Connexion WebSocket : authentifiée par cookie, abonnements par salon."""
    redis = websocket.app.state.redis
    hub: InProcessHub = websocket.app.state.hub

    # 1. Authentification — le cookie de session doit être valide.
    session = get_session(redis, websocket)
    if session is None:
        await websocket.close(code=4401)
        return
    user_id = session.get("user_id")

    # 2. Vérification d'origine (anti cross-site WebSocket hijacking).
    if not origin_matches_host(websocket):
        await websocket.close(code=1008)
        return

    await websocket.accept()
    try:
        while True:
            message = await websocket.receive_json()
            await _handle_message(
                websocket,
                hub,
                message,
                redis=redis,
                user_id=user_id,
            )
    except (WebSocketDisconnect, json.JSONDecodeError):
        pass
    finally:
        hub.disconnect(websocket)
