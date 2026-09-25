"""Gestion des connexions WebSocket : diffusion, présence, frappe en cours.

Chaque message échangé porte un champ `type`, ce qui permet de faire passer
plusieurs flux sur la même connexion :

    message          un message chiffré vient d'être posté
    message_updated  un message a été réédité par son auteur
    message_deleted  un message a été retiré
    presence         la liste des membres actuellement connectés
    typing           quelqu'un est en train d'écrire
    error            la requête précédente a été refusée

Un même utilisateur peut avoir plusieurs onglets ouverts : la présence
raisonne donc par utilisateur, pas par connexion.
"""

from fastapi import WebSocket


class ConnectionManager:
    def __init__(self):
        # salon_id -> {websocket: {"user_id": ..., "username": ...}}
        self.active_connections: dict[str, dict[WebSocket, dict]] = {}

    async def connect(self, salon_id: str, websocket: WebSocket, user_id: str, username: str):
        await websocket.accept()
        self.active_connections.setdefault(salon_id, {})[websocket] = {
            "user_id": user_id,
            "username": username,
        }

    def disconnect(self, salon_id: str, websocket: WebSocket):
        connections = self.active_connections.get(salon_id)
        if not connections:
            return
        connections.pop(websocket, None)
        if not connections:
            del self.active_connections[salon_id]

    def online_users(self, salon_id: str) -> list[dict]:
        """Membres connectés, dédoublonnés : deux onglets ne comptent qu'une fois."""
        seen: dict[str, dict] = {}
        for info in self.active_connections.get(salon_id, {}).values():
            seen[info["user_id"]] = {"user_id": info["user_id"], "username": info["username"]}
        return sorted(seen.values(), key=lambda u: u["username"].lower())

    def connection_count(self, salon_id: str) -> int:
        return len(self.active_connections.get(salon_id, {}))

    async def broadcast(self, salon_id: str, message: dict, exclude: WebSocket | None = None):
        """Diffuse à tout le salon, en écartant les connexions mortes."""
        dead: list[WebSocket] = []
        for connection in list(self.active_connections.get(salon_id, {})):
            if connection is exclude:
                continue
            try:
                await connection.send_json(message)
            except Exception:  # noqa: BLE001 - une socket fermée ne doit pas casser la diffusion
                dead.append(connection)
        for connection in dead:
            self.disconnect(salon_id, connection)

    async def broadcast_presence(self, salon_id: str):
        await self.broadcast(salon_id, {"type": "presence", "users": self.online_users(salon_id)})


manager = ConnectionManager()
