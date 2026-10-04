"""Messages : le serveur ne voit que du chiffré."""

import json
import secrets
from datetime import datetime, timezone

from fastapi import APIRouter, Depends

from app.database import db
from app.models import EncryptedMessage
from app.permissions import channel_in_server, member
from app.security import csrf, current_user

router = APIRouter()

# Nombre de messages renvoyés pour un canal
HISTORY_SIZE = 100


# Les derniers messages chiffrés du canal
@router.get("/servers/{server_id}/channels/{channel_id}/messages")
async def list_messages(
    server_id: str, channel_id: str, user_id: str = Depends(current_user), database=Depends(db)
):
    await member(server_id, user_id, database)
    await channel_in_server(server_id, channel_id, database)
    rows = await database.lrange(f"channel:{channel_id}:messages", -HISTORY_SIZE, -1)
    return [json.loads(row) for row in rows]


# Envoi d'un message chiffré, le serveur le stocke tel quel
@router.post("/servers/{server_id}/channels/{channel_id}/messages", dependencies=[Depends(csrf)])
async def send_message(
    server_id: str, channel_id: str, data: EncryptedMessage,
    user_id: str = Depends(current_user), database=Depends(db),
):
    await member(server_id, user_id, database)
    await channel_in_server(server_id, channel_id, database)
    message = {
        "id": secrets.token_urlsafe(12),
        "author": await database.hget(f"user:{user_id}", "username"),
        "created_at": datetime.now(timezone.utc).isoformat(),
        "version": data.version, "nonce": data.nonce, "ciphertext": data.ciphertext,
    }
    await database.rpush(f"channel:{channel_id}:messages", json.dumps(message))
    return message
