"""ConnectionManager : registre des sockets WebSocket par salon.

Le serveur ne « comprend » JAMAIS le contenu : il route des blobs opaques
entre membres. Sa seule logique = connecter / déconnecter / relayer,
l'identité étant fournie par la session signée (voir routers/ws.py).
"""

import logging
from typing import Any

from starlette.websockets import WebSocket

logger = logging.getLogger("talk.realtime")


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

    async def disconnect_user(self, room_id: str, username: str) -> None:
        """Ferme toutes les sockets d'un membre qui vient de QUITTER le salon.

        Le routeur HTTP a déjà diffusé `member_left` : on retire juste les
        sockets restantes, sans nouvelle notification (sinon un « leave »
        apparaîtrait en plus — inutile, le membre n'existe plus).
        """
        room = self._rooms.get(room_id)
        if room is None:
            return
        for websocket, name in list(room.items()):
            if name != username:
                continue
            room.pop(websocket, None)
            try:
                await websocket.close(code=1000, reason="salon quitté")
            except Exception:
                logger.debug("socket de %s déjà fermée (salon %s)", username, room_id)
        if not room:
            self._rooms.pop(room_id, None)

    async def disconnect_room(self, room_id: str) -> None:
        """Ferme toutes les sockets d'un salon supprimé (aucun rejeu)."""
        room = self._rooms.pop(room_id, None)
        if room is None:
            return
        for websocket in list(room.keys()):
            try:
                await websocket.close(code=1000, reason="salon supprimé")
            except Exception:
                logger.debug("socket déjà fermée lors de la suppression du salon %s", room_id)

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

    def online_users(self, room_id: str) -> set[str]:
        """Pseudos actuellement connectés dans un salon (panneau « membres »)."""
        return set(self._rooms.get(room_id, {}).values())

    @property
    def rooms(self) -> dict[str, dict[WebSocket, str]]:
        return self._rooms


# Singleton partagé : ws.py (connexions) et rooms.py (présence/invités) s'en
# servent. Un seul registre, sinon les broadcasts et le statut online divergent.
manager = ConnectionManager()
