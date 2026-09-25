import contextlib

from fastapi import WebSocket


class ConnectionManager:
    def __init__(self):
        self.active_connections: dict[str, list[WebSocket]] = {}

    async def connect(self, salon_id: str, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.setdefault(salon_id, []).append(websocket)

    def disconnect(self, salon_id: str, websocket: WebSocket):
        connections = self.active_connections.get(salon_id)
        if not connections:
            return
        if websocket in connections:
            connections.remove(websocket)
        if not connections:
            del self.active_connections[salon_id]

    async def broadcast(self, salon_id: str, message: dict):
        """Diffuse à tout le salon, en écartant les connexions mortes."""
        dead: list[WebSocket] = []
        for connection in list(self.active_connections.get(salon_id, [])):
            try:
                await connection.send_json(message)
            except Exception:  # noqa: BLE001 - une socket fermée ne doit pas casser la diffusion
                dead.append(connection)
        for connection in dead:
            with contextlib.suppress(ValueError):
                self.disconnect(salon_id, connection)


manager = ConnectionManager()
