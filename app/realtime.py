import asyncio
from collections import defaultdict
from typing import Dict, Iterable, Set

from fastapi import WebSocket


class ConnectionManager:
    """Diffuse les événements aux WebSockets des membres d'un salon."""

    def __init__(self) -> None:
        self._connections: Dict[str, Set[WebSocket]] = defaultdict(set)
        self._lock = asyncio.Lock()

    async def connect(self, user_id: str, websocket: WebSocket) -> None:
        await websocket.accept()
        async with self._lock:
            self._connections[user_id].add(websocket)

    async def disconnect(self, user_id: str, websocket: WebSocket) -> None:
        async with self._lock:
            sockets = self._connections.get(user_id)
            if not sockets:
                return
            sockets.discard(websocket)
            if not sockets:
                self._connections.pop(user_id, None)

    async def broadcast_to_users(
        self, user_ids: Iterable[str], payload: Dict[str, object]
    ) -> None:
        recipients = set(user_ids)
        async with self._lock:
            sockets = {
                socket
                for user_id in recipients
                for socket in self._connections.get(user_id, set())
            }
        if not sockets:
            return
        results = await asyncio.gather(
            *(socket.send_json(payload) for socket in sockets),
            return_exceptions=True,
        )
        failed = [socket for socket, result in zip(sockets, results) if isinstance(result, Exception)]
        if failed:
            async with self._lock:
                for user_id, user_sockets in list(self._connections.items()):
                    for socket in failed:
                        user_sockets.discard(socket)
                    if not user_sockets:
                        self._connections.pop(user_id, None)

    async def connection_count(self, user_id: str) -> int:
        async with self._lock:
            return len(self._connections.get(user_id, set()))
