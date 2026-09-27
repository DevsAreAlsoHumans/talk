from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from app.security import SecurityUtils
from app.models import MessageCreate, Message, MessageType
from app.database import get_redis
import secrets
from datetime import datetime

router = APIRouter(prefix="/api/messages", tags=["messages"])

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/login")

# Stockage en mémoire (à remplacer par Redis)
_messages_db = {}


async def get_current_user_id(token: str = Depends(oauth2_scheme)) -> str:
    """Récupère l'ID utilisateur depuis le token."""
    return SecurityUtils.extract_user_id_from_token(token)


@router.get("/room/{room_id}", response_model=list[Message])
async def list_messages(room_id: str, token: str = Depends(oauth2_scheme)):
    """Liste les messages d'un salon."""
    user_id = await get_current_user_id(token)
    # Vérifier que l'utilisateur fait partie du salon
    messages = [m for m in _messages_db.values() if m["room_id"] == room_id]
    return sorted(messages, key=lambda m: m["created_at"])


@router.post("/", response_model=Message, status_code=status.HTTP_201_CREATED)
async def send_message(message_data: MessageCreate, token: str = Depends(oauth2_scheme)):
    """Envoie un message dans un salon."""
    user_id = await get_current_user_id(token)

    message_id = f"msg_{secrets.token_urlsafe(8)}"
    message = {
        "id": message_id,
        "room_id": message_data.room_id,
        "user_id": user_id,
        "content": message_data.content,  # Contenu chiffré E2E
        "message_type": message_data.message_type,
        "encrypted": message_data.encrypted,
        "created_at": datetime.utcnow()
    }
    _messages_db[message_id] = message

    return message


@router.get("/{message_id}", response_model=Message)
async def get_message(message_id: str, token: str = Depends(oauth2_scheme)):
    """Récupère un message."""
    message = _messages_db.get(message_id)
    if not message:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Message non trouvé"
        )
    return message


@router.delete("/{message_id}")
async def delete_message(message_id: str, token: str = Depends(oauth2_scheme)):
    """Supprime un message."""
    user_id = await get_current_user_id(token)
    message = _messages_db.get(message_id)
    if not message:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Message non trouvé"
        )
    if message["user_id"] != user_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Non autorisé"
        )

    del _messages_db[message_id]
    return {"message": "Message supprimé"}