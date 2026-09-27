"""Temps reel : WebSocket par canal, diffusion des enveloppes chiffrees.

Le serveur ne relaie que des donnees deja chiffrees. L'authentification
reprend le cookie de session, et l'origine est verifiee afin de bloquer le
vol de session par site tiers (WebSocket ignore la politique SOP du navigateur).

Le gestionnaire de connexions est en memoire : il couvre un processus uvicorn.
Pour plusieurs workers, remplacer la diffusion par un Redis Pub/Sub.
"""

import json
from urllib.parse import urlsplit

from fastapi import APIRouter, HTTPException, WebSocket, WebSocketDisconnect, status
from pydantic import ValidationError
from redis import Redis
from starlette.websockets import WebSocketState

from app.config import Settings, get_settings
from app.db import get_redis
from app.repositories import messages, salons, users
from app.schemas_chat import MessageEnvelopeIn
from app.security.ratelimit import enforce_rate_limit
from app.security.sessions import SESSION_COOKIE, read_session

router = APIRouter()

POLICY_VIOLATION = status.WS_1008_POLICY_VIOLATION


class ConnectionManager:
    """Salles de diffusion, une par canal."""

    def __init__(self) -> None:
        self._rooms: dict[str, set[WebSocket]] = {}

    def join(self, channel_id: str, socket: WebSocket) -> None:
        self._rooms.setdefault(channel_id, set()).add(socket)

    def leave(self, channel_id: str, socket: WebSocket) -> None:
        room = self._rooms.get(channel_id)
        if room is not None:
            room.discard(socket)
            if not room:
                self._rooms.pop(channel_id, None)

    def count(self, channel_id: str) -> int:
        return len(self._rooms.get(channel_id, ()))

    async def broadcast(self, channel_id: str, frame: dict) -> None:
        payload = json.dumps(frame)
        for socket in tuple(self._rooms.get(channel_id, ())):
            try:
                if socket.client_state is WebSocketState.CONNECTED:
                    await socket.send_text(payload)
            except (WebSocketDisconnect, RuntimeError):
                self.leave(channel_id, socket)


manager = ConnectionManager()


def _origin_allowed(socket: WebSocket) -> bool:
    """ meme origine que la requete, sinon la connexion est refusee."""
    origin = socket.headers.get("origin")
    if not origin:
        return True  # client non navigateur (tests, CLI)
    host = socket.headers.get("host")
    return urlsplit(origin).netloc == host


def _authenticate(socket: WebSocket, channel_id: str) -> dict | None:
    redis = get_redis()
    session = read_session(redis, socket.cookies.get(SESSION_COOKIE))
    if session is None:
        return None
    user = users.get_by_id(redis, str(session.get("user_id", "")))
    if user is None:
        return None
    if salons.can_access_channel(redis, channel_id, user["id"]) is None:
        return None
    return user


def _error(socket: WebSocket, code: str, detail: str) -> None:
    socket.send_text(json.dumps({"type": "error", "code": code, "detail": detail}))


@router.websocket("/ws/channels/{channel_id}")
async def channel_socket(socket: WebSocket, channel_id: str) -> None:
    if not _origin_allowed(socket):
        await socket.close(code=POLICY_VIOLATION)
        return
    user = _authenticate(socket, channel_id)
    if user is None:
        await socket.close(code=POLICY_VIOLATION)
        return

    await socket.accept()
    redis = get_redis()
    manager.join(channel_id, socket)
    settings = get_settings()
    socket.send_text(
        json.dumps(
            {
                "type": "ready",
                "channel_id": channel_id,
                "user_id": user["id"],
                "latest_seq": messages.latest_sequence(redis, channel_id),
            }
        )
    )
    try:
        while True:
            raw = await socket.receive_text()
            await _handle_frame(socket, raw, redis, channel_id, user, settings)
    except WebSocketDisconnect:
        manager.leave(channel_id, socket)
    except RuntimeError:
        manager.leave(channel_id, socket)


async def _handle_frame(
    socket: WebSocket,
    raw: str,
    redis: Redis,
    channel_id: str,
    user: dict,
    settings: Settings,
) -> None:
    if len(raw) > 20000:
        _error(socket, "too_large", "Enveloppe trop volumineuse.")
        return
    try:
        payload = MessageEnvelopeIn.model_validate_json(raw)
    except ValidationError:
        _error(socket, "invalid_envelope", "Enveloppe invalide : contenu chiffre attendu.")
        return
    try:
        enforce_rate_limit(
            redis,
            f"ratelimit:message:{user['id']}",
            limit=settings.rate_limit_message_max,
            window=settings.rate_limit_message_window,
        )
    except HTTPException:
        _error(socket, "rate_limited", "Trop de messages, ralentissez.")
        return
    envelope = messages.store_message(
        redis,
        channel_id=channel_id,
        sender_id=user["id"],
        ciphertext=payload.ciphertext,
        iv=payload.iv,
        key_version=payload.key_version,
    )
    await manager.broadcast(channel_id, {"type": "message", "message": envelope})
