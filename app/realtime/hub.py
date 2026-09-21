"""Hub de diffusion temps réel, en mémoire (in-process).

Maintient l'association ``salon → set[WebSocket]`` et diffuse les événements
(``new_message``, ``member_joined``) aux abonnés. Conçu pour un worker unique
(défaut uvicorn) ; avec plusieurs workers il faudrait un pub/sub Redis.
"""

from __future__ import annotations

import threading
from collections import defaultdict

from fastapi import Request, WebSocket


class InProcessHub:
    """Diffuse des événements JSON aux WebSockets abonnés, par salon."""

    def __init__(self) -> None:
        self._rooms: dict[str, set[WebSocket]] = defaultdict(set)
        self._socket_rooms: dict[WebSocket, set[str]] = defaultdict(set)
        self._socket_user: dict[WebSocket, str] = {}
        self._lock = threading.RLock()

    def attach_user(self, websocket: WebSocket, user_id: str) -> None:
        """Enregistre le lien ``socket → user_id`` (présence et leave).

        Permet de retrouver tous les sockets d'un utilisateur, notamment pour
        le désabonner d'un salon qu'il quitte.
        """
        with self._lock:
            self._socket_user[websocket] = user_id

    def subscribe(self, room_id: str, websocket: WebSocket) -> None:
        """Abonne un socket à un salon."""
        with self._lock:
            self._rooms[room_id].add(websocket)
            self._socket_rooms[websocket].add(room_id)

    def unsubscribe(self, room_id: str, websocket: WebSocket) -> None:
        """Désabonne un socket d'un salon."""
        with self._lock:
            self._rooms.get(room_id, set()).discard(websocket)
            self._socket_rooms.get(websocket, set()).discard(room_id)

    def unsubscribe_user_room(self, user_id: str, room_id: str) -> None:
        """Retire tous les sockets d'un utilisateur du salon (leave).

        Chaque socket du compte est retiré du salon dans ``_rooms`` comme
        dans son registre ``_socket_rooms`` — même sémantique que
        ``unsubscribe``, appliquée à l'ensemble des onglets de l'utilisateur.
        """
        with self._lock:
            for websocket, owner_id in list(self._socket_user.items()):
                if owner_id == user_id:
                    self._rooms.get(room_id, set()).discard(websocket)
                    self._socket_rooms.get(websocket, set()).discard(room_id)

    def disconnect(self, websocket: WebSocket) -> None:
        """Retire un socket de tous les salons (connexion fermée)."""
        with self._lock:
            for room_id in self._socket_rooms.pop(websocket, set()):
                self._rooms.get(room_id, set()).discard(websocket)
            self._socket_user.pop(websocket, None)

    async def publish(self, room_id: str, event: dict) -> None:
        """Diffuse ``event`` (JSON) à tous les abonnés du salon.

        Les sockets en erreur (déconnectés) sont retirés du hub.
        """
        with self._lock:
            targets = list(self._rooms.get(room_id, set()))
        dead: list[WebSocket] = []
        for websocket in targets:
            try:
                await websocket.send_json(event)
            except Exception:
                dead.append(websocket)
        for websocket in dead:
            self.disconnect(websocket)


def get_hub(request: Request) -> InProcessHub:
    """Dépendance FastAPI : renvoie le hub posé sur ``app.state.hub``."""
    return request.app.state.hub
