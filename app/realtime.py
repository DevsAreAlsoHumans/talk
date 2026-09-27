"""Registre des connexions WebSocket, indexé par canal.

Limite assumée du MVP : ce registre vit dans la mémoire du processus. Avec
plusieurs workers uvicorn, un message ne serait reçu que par les clients
connectés au worker qui l'a traité. Le MVP impose donc un seul worker ; une
montée en charge demanderait un mécanisme de diffusion partagé, par exemple des
change streams MongoDB sur un replica set.
"""

from __future__ import annotations

import asyncio
from typing import Any

from fastapi import WebSocket


class ConnectionManager:
    """Table de diffusion : un canal, un ensemble de WebSockets abonnés."""

    def __init__(self) -> None:
        self._subscribers: dict[str, set[WebSocket]] = {}
        self._channels_by_socket: dict[WebSocket, set[str]] = {}
        self._lock = asyncio.Lock()

    async def connect(self, websocket: WebSocket) -> None:
        async with self._lock:
            self._channels_by_socket.setdefault(websocket, set())

    async def subscribe(self, channel_id: str, websocket: WebSocket) -> None:
        async with self._lock:
            self._subscribers.setdefault(channel_id, set()).add(websocket)
            self._channels_by_socket.setdefault(websocket, set()).add(channel_id)

    async def unsubscribe(self, channel_id: str, websocket: WebSocket) -> None:
        async with self._lock:
            self._channels_by_socket.get(websocket, set()).discard(channel_id)
            subscribers = self._subscribers.get(channel_id)
            if subscribers is not None:
                subscribers.discard(websocket)
                if not subscribers:
                    del self._subscribers[channel_id]

    async def disconnect(self, websocket: WebSocket) -> None:
        """Retire la socket de tous les canaux auxquels elle était abonnée."""
        async with self._lock:
            for channel_id in self._channels_by_socket.pop(websocket, set()):
                subscribers = self._subscribers.get(channel_id)
                if subscribers is not None:
                    subscribers.discard(websocket)
                    if not subscribers:
                        del self._subscribers[channel_id]

    def subscriber_count(self, channel_id: str) -> int:
        """Nombre de sockets actuellement abonnées à un canal.

        Synchrone et sans verrou : c'est une lecture d'un dictionnaire, appelée
        par les tests et le diagnostic, jamais depuis le chemin d'un message.
        """
        return len(self._subscribers.get(channel_id, ()))

    async def broadcast(
        self, channel_id: str, payload: dict[str, Any], exclude: WebSocket | None = None
    ) -> None:
        """Diffuse une trame aux abonnés d'un canal, sauf à l'émetteur.

        Le payload est déjà un ciphertext : le registre n'a aucun moyen de le
        déchiffrer, il ne fait que le recopier.
        """
        async with self._lock:
            targets = list(self._subscribers.get(channel_id, ()))
        for websocket in targets:
            if websocket is exclude:
                continue
            try:
                await websocket.send_json(payload)
            except RuntimeError:
                # Connexion tombée entre-temps : la diffusion ignore ce client.
                await self.disconnect(websocket)


# Instance partagée par le processus.
connection_manager = ConnectionManager()
