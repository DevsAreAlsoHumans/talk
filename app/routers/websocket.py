from fastapi import APIRouter, WebSocket, WebSocketDisconnect, Depends
from fastapi.security import OAuth2PasswordBearer
from app.security import SecurityUtils
import json
from typing import Dict
import secrets
from datetime import datetime

router = APIRouter(prefix="/ws", tags=["websocket"])

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/login")

# Connexions WebSocket actives
_connections: Dict[str, WebSocket] = {}


@router.websocket("/")
async def websocket_endpoint(websocket: WebSocket, token: str = Depends(oauth2_scheme)):
    """Point de terminaison WebSocket."""
    try:
        # Vérifier le token et obtenir l'user_id
        user_id = SecurityUtils.extract_user_id_from_token(token)

        # Accepter la connexion
        await websocket.accept()

        # Stocker la connexion WebSocket
        connection_id = f"conn_{secrets.token_urlsafe(8)}"
        _connections[connection_id] = {
            "websocket": websocket,
            "user_id": user_id,
            "room_id": None,
            "connected_at": datetime.utcnow()
        }

        try:
            while True:
                # Recevoir les données du client
                data = await websocket.receive_text()
                message_data = json.loads(data)

                # Traiter le message
                action = message_data.get("action")
                room_id = message_data.get("room_id")

                if action == "join_room":
                    # Rejoindre un salon
                    _connections[connection_id]["room_id"] = room_id
                    await websocket.send_text(json.dumps({
                        "type": "joined_room",
                        "room_id": room_id
                    }))

                elif action == "send_message":
                    # Envoyer un message
                    content = message_data.get("content")
                    encrypted = message_data.get("encrypted", True)

                    # En production, vérifier les permissions et émettre via Redis
                    # Pour l'exemple, on envoie juste un message de confirmation
                    await websocket.send_text(json.dumps({
                        "type": "message_sent",
                        "room_id": room_id,
                        "content": f"Message reçu (chiffré: {encrypted})",
                        "timestamp": datetime.utcnow().isoformat()
                    }))

                elif action == "ping":
                    # Pong
                    await websocket.send_text(json.dumps({
                        "type": "pong"
                    }))

        except WebSocketDisconnect:
            pass
        finally:
            # Nettoyer la connexion
            if connection_id in _connections:
                del _connections[connection_id]

    except Exception as e:
        # Envoyer une erreur au client
        await websocket.close(code=1008, reason=str(e))


@router.get("/connections")
async def get_connections():
    """Récupère les connexions WebSocket actives (debug)."""
    return {
        "total_connections": len(_connections),
        "connections": [
            {
                "id": cid,
                "user_id": conn["user_id"],
                "room_id": conn["room_id"],
                "connected_at": conn["connected_at"].isoformat()
            }
            for cid, conn in _connections.items()
        ]
    }