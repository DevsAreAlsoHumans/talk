"""ConnectionManager : registre des sockets WebSocket par salon.

Le serveur ne « comprend » JAMAIS le contenu : il route des blobs opaques
entre membres. Sa seule logique = connecter / déconnecter / relayer,
l'identité étant fournie par la session signée (voir routers/ws.py).
"""

from typing import Any

from starlette.websockets import WebSocket


class ConnectionManager:
    def __init__(self) -> None:
        # room_id -> {websocket: username}
        self._rooms: dict[str, dict[WebSocket, str]] = {}

    async def connect(self, room_id: str, websocket: WebSocket, username: str) -> None:
        """Accepte la socket et l'enregistre dans le salon."""
        await websocket.accept()
        self._rooms.setdefault(room_id, {})[websocket] = username
        # Enveloppe de présence : les autres membres savent qui est en ligne,
        # sans qu'aucun contenu ne fuie.
        await self.broadcast(
            room_id,
            {"type": "presence", "event": "join", "user": username},
            exclude=websocket,
        )

    async def disconnect(self, room_id: str, websocket: WebSocket) -> None:
        """Retire la socket du salon et notifie la sortie."""
        room = self._rooms.get(room_id)
        if room is None:
            return
        username = room.pop(websocket, None)
        if not room:
            self._rooms.pop(room_id, None)
        if username:
            await self.broadcast(
                room_id,
                {"type": "presence", "event": "leave", "user": username},
            )

    async def broadcast(
        self,
        room_id: str,
        payload: dict[str, Any],
        *,
        exclude: WebSocket | None = None,
    ) -> None:
        """Distribue un payload opaque à tous les membres SAUF l'émetteur.

        L'émetteur affiche son propre message côté client (rendu optimiste) :
        le serveur ne relaie que vers les « autres membres du salon ».
        """
        room = self._rooms.get(room_id)
        if not room:
            return
        for websocket in list(room.keys()):  # copie : on peut retirer pendant l'itération
            if websocket is exclude:
                continue
            try:
                await websocket.send_json(payload)
            except Exception:
                # Socket tombée (client fermé, réseau coupé) : on l'évacue.
                room.pop(websocket, None)

    @property
    def rooms(self) -> dict[str, dict[WebSocket, str]]:
        return self._rooms
