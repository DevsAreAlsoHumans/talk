import asyncio
from collections import defaultdict
from collections.abc import Iterable
from typing import Optional

from fastapi import WebSocket

from app.storage import RedisStore


class ConnectionManager:
    """Diffuse les événements aux WebSockets des membres d'un salon."""

    def __init__(self, session_store: Optional[RedisStore] = None) -> None:
        self._connections: dict[str, dict[WebSocket, str]] = defaultdict(dict)
        self._session_store = session_store
        self._lock = asyncio.Lock()

    def set_session_store(self, session_store: RedisStore) -> None:
        self._session_store = session_store

    async def connect(self, user_id: str, websocket: WebSocket, session_hash: str) -> None:
        await websocket.accept()
        async with self._lock:
            self._connections[user_id][websocket] = session_hash

    async def disconnect(self, user_id: str, websocket: WebSocket) -> None:
        async with self._lock:
            sockets = self._connections.get(user_id)
            if not sockets:
                return
            sockets.pop(websocket, None)
            if not sockets:
                self._connections.pop(user_id, None)

    def _remove_sockets(self, sockets_to_remove: set[WebSocket]) -> None:
        for user_id, user_sockets in list(self._connections.items()):
            for websocket in sockets_to_remove:
                user_sockets.pop(websocket, None)
            if not user_sockets:
                self._connections.pop(user_id, None)

    async def disconnect_session(self, session_hash: str) -> None:
        async with self._lock:
            sockets = {
                websocket
                for user_sockets in self._connections.values()
                for websocket, connected_hash in user_sockets.items()
                if connected_hash == session_hash
            }
            self._remove_sockets(sockets)
        if sockets:
            await asyncio.gather(
                *(websocket.close(code=4401, reason="Session révoquée") for websocket in sockets),
                return_exceptions=True,
            )

    async def broadcast_to_users(self, user_ids: Iterable[str], payload: dict[str, object]) -> None:
        recipients = set(user_ids)
        async with self._lock:
            connections = [
                (user_id, websocket, session_hash)
                for user_id in recipients
                for websocket, session_hash in self._connections.get(user_id, {}).items()
            ]
        if not connections:
            return

        valid_connections = connections
        if self._session_store is not None:
            session_cache: dict[str, bool] = {}
            invalid_sockets: set[WebSocket] = set()
            for user_id, websocket, session_hash in connections:
                if session_hash not in session_cache:
                    session = await self._session_store.get_session(session_hash)
                    session_cache[session_hash] = bool(session and session["user_id"] == user_id)
                if not session_cache[session_hash]:
                    invalid_sockets.add(websocket)
            if invalid_sockets:
                async with self._lock:
                    self._remove_sockets(invalid_sockets)
                await asyncio.gather(
                    *(
                        websocket.close(code=4401, reason="Session expirée")
                        for websocket in invalid_sockets
                    ),
                    return_exceptions=True,
                )
            valid_connections = [
                connection for connection in connections if connection[1] not in invalid_sockets
            ]

        sockets = [connection[1] for connection in valid_connections]
        if not sockets:
            return
        results = await asyncio.gather(
            *(socket.send_json(payload) for socket in sockets),
            return_exceptions=True,
        )
        failed = {
            socket for socket, result in zip(sockets, results) if isinstance(result, Exception)
        }
        if failed:
            async with self._lock:
                self._remove_sockets(failed)

    async def connection_count(self, user_id: str) -> int:
        async with self._lock:
            return len(self._connections.get(user_id, {}))
