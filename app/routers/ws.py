"""WebSocket du chat : canaux multi-utilisateurs, payloads opaques (E2EE).

Le serveur :
  1. vérifie l'identité via la session signée (cookie du handshake HTTP),
  2. s'assure que l'user est membre du salon,
  3. lit l'enveloppe {channel, payload} : le canal doit appartenir au salon,
  4. NE TOUCHE PAS au payload : blob chiffré opaque, transmis tel quel aux
     autres membres par ConnectionManager.

Seul « channel » est de la métadonnée (routage Discord) ; le contenu reste
chiffré de bout en bout et jamais interprété côté serveur.
"""

import asyncio
import json
from typing import Annotated
from urllib.parse import urlsplit

from fastapi import (
    APIRouter,
    Depends,
    Query,
    WebSocket,
    WebSocketDisconnect,
)

from ..config import get_settings
from ..db import Database, get_db
from ..deps import SESSION_COOKIE
from ..realtime import ConnectionManager
from ..security import verify_session_token

router = APIRouter(prefix="/api/ws", tags=["ws"])

# Code d'état applicatif (>3000 : zone privée du protocole) :
WS_UNAUTHENTICATED = 4401  # session absente/invalide ou non membre du salon
WS_BAD_ENVELOPE = 4402     # enveloppe mal formée ou canal inconnu du salon
WS_MESSAGE_TOO_LARGE = 4409
WS_POLICY_VIOLATION = 1008  # origine tierce non autorisée

# Plafond explicite : un blob chiffré est borné — au-delà, refus.
MAX_PAYLOAD_BYTES = 64 * 1024

manager = ConnectionManager()

DbDep = Annotated[Database, Depends(get_db)]


async def _authenticated_username(websocket: WebSocket, db: Database) -> str | None:
    """Identité depuis le cookie de session du handshake.

    Le cookie voyage dans l'en-tête HTTP initial, pas dans les frames : on le
    lit ici, une seule fois, avant tout échange.
    """
    token = websocket.cookies.get(SESSION_COOKIE)
    if not token:
        return None
    session = verify_session_token(token)
    if session is None:
        return None
    user = await db.get_user_by_id(session["uid"])
    return user["username"] if user else None


def _frame_payload(raw: str) -> tuple[str, str] | None:
    """Décode {channel, payload} — sinon None (enveloppe rejetée)."""
    try:
        frame = json.loads(raw)
    except (json.JSONDecodeError, ValueError):
        return None
    if not isinstance(frame, dict):
        return None
    channel_id = frame.get("channel")
    payload = frame.get("payload")
    if not isinstance(channel_id, str) or not isinstance(payload, str):
        return None
    return channel_id, payload


def _origin_allowed(websocket: WebSocket) -> bool:
    """Défense en profondeur : un site tiers ne doit pas pouvoir ouvrir de
    socket vers nous (cross-site WebSocket hijacking). Accepte :
      - aucune origine (client non-navigateur : bots, tests),
      - une origine explicite de la allowlist CORS,
      - la même origine que la nôtre (host du handshake)."""
    origin = websocket.headers.get("origin")
    if not origin:
        return True
    try:
        parts = urlsplit(origin)
    except ValueError:
        return False
    if parts.scheme not in {"http", "https"}:
        return False
    if origin in get_settings().cors_origins:
        return True
    host = websocket.headers.get("host")
    return bool(host) and parts.netloc == host


async def _close_socket(websocket: WebSocket, room_id: str, code: int) -> None:
    """Fermeture propre : évacue d'abord le manager (pas de fuite de socket)."""
    await manager.disconnect(room_id, websocket)
    await websocket.close(code=code)


@router.websocket("")
async def chat_ws(
    websocket: WebSocket,
    room_id: str = Query(min_length=1, max_length=64),
    db: DbDep = ...,
):
    username = await _authenticated_username(websocket, db)
    if username is None:
        await websocket.close(code=WS_UNAUTHENTICATED)
        return

    if not _origin_allowed(websocket):
        await websocket.close(code=WS_POLICY_VIOLATION)
        return

    room = await db.get_room_by_id(room_id)
    # Même comportement pour salon inexistant OU non-membre : pas de fuite
    # d'information sur l'existence des salons (énumération).
    if room is None or username not in room["members"]:
        await websocket.close(code=WS_UNAUTHENTICATED)
        return

    await manager.connect(room_id, websocket, username)
    try:
        while True:
            raw = await websocket.receive_text()
            frame = _frame_payload(raw)
            if frame is None:
                await _close_socket(websocket, room_id, WS_BAD_ENVELOPE)
                return
            channel_id, payload = frame
            # Plafond sur le payload seul : la métadonnée est négligeable.
            if len(payload.encode()) > MAX_PAYLOAD_BYTES:
                await _close_socket(websocket, room_id, WS_MESSAGE_TOO_LARGE)
                return
            # Le canal doit appartenir à ce salon (anti-crosstalk multi-salons).
            channel = await db.get_channel(room_id, channel_id)
            if channel is None:
                await _close_socket(websocket, room_id, WS_BAD_ENVELOPE)
                return
            # Persistance chiffrée : le client rejouera cet historique au besoin.
            record = await db.add_channel_message(room_id, channel_id, username, payload)
            if record is None:  # canal supprimé entre-temps : on ne relaie pas
                continue
            await manager.broadcast(
                room_id,
                {
                    "room_id": room_id,
                    "channel_id": channel_id,
                    "from": username,
                    "payload": payload,
                    "n": record["n"],
                    "ts": record["ts"].isoformat(),
                },
                exclude=websocket,
            )
    except WebSocketDisconnect:
        await manager.disconnect(room_id, websocket)
    except asyncio.CancelledError:
        await manager.disconnect(room_id, websocket)
        raise
