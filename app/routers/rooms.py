from fastapi import APIRouter, Depends, HTTPException, status, WebSocket, WebSocketDisconnect
from fastapi.security import OAuth2PasswordBearer
from app.security import SecurityUtils
from app.models import RoomCreate, Room, RoomMember, RoomType
from app.database import get_redis
import secrets
from datetime import datetime

router = APIRouter(prefix="/api/rooms", tags=["rooms"])

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/login")

# Stockage en mémoire (à remplacer par Redis)
_rooms_db = {}
_room_members_db = {}


async def get_current_user_id(token: str = Depends(oauth2_scheme)) -> str:
    """Récupère l'ID utilisateur depuis le token."""
    return SecurityUtils.extract_user_id_from_token(token)


@router.get("/", response_model=list[Room])
async def list_rooms(token: str = Depends(oauth2_scheme)):
    """Liste tous les salons publics."""
    rooms = []
    for room in _rooms_db.values():
        if not room.get("is_private"):
            rooms.append(room)
    return rooms


@router.get("/{room_id}", response_model=Room)
async def get_room(room_id: str, token: str = Depends(oauth2_scheme)):
    """Récupère un salon par ID."""
    room = _rooms_db.get(room_id)
    if not room:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Salon non trouvé"
        )
    return room


@router.post("/", response_model=Room, status_code=status.HTTP_201_CREATED)
async def create_room(room_data: RoomCreate, token: str = Depends(oauth2_scheme)):
    """Crée un nouveau salon."""
    user_id = await get_current_user_id(token)

    room_id = f"room_{secrets.token_urlsafe(8)}"
    room = {
        "id": room_id,
        "name": room_data.name,
        "description": room_data.description,
        "room_type": room_data.room_type,
        "is_private": room_data.is_private,
        "parent_server": room_data.parent_server,
        "created_by": user_id,
        "created_at": datetime.utcnow(),
        "member_count": 1
    }
    _rooms_db[room_id] = room

    # Ajouter le créateur comme membre
    _room_members_db[f"{room_id}:{user_id}"] = {
        "id": f"member_{secrets.token_urlsafe(4)}",
        "room_id": room_id,
        "user_id": user_id,
        "role": "owner",
        "joined_at": datetime.utcnow()
    }

    return room


@router.put("/{room_id}", response_model=Room)
async def update_room(room_id: str, room_data: RoomCreate, token: str = Depends(oauth2_scheme)):
    """Met à jour un salon."""
    user_id = await get_current_user_id(token)
    room = _rooms_db.get(room_id)
    if not room:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Salon non trouvé"
        )
    if room["created_by"] != user_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Non autorisé"
        )

    room["name"] = room_data.name
    room["description"] = room_data.description
    room["is_private"] = room_data.is_private
    _rooms_db[room_id] = room

    return room


@router.delete("/{room_id}")
async def delete_room(room_id: str, token: str = Depends(oauth2_scheme)):
    """Supprime un salon."""
    user_id = await get_current_user_id(token)
    room = _rooms_db.get(room_id)
    if not room:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Salon non trouvé"
        )
    if room["created_by"] != user_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Non autorisé"
        )

    del _rooms_db[room_id]
    return {"message": "Salon supprimé"}


@router.post("/{room_id}/join")
async def join_room(room_id: str, token: str = Depends(oauth2_scheme)):
    """Rejoint un salon."""
    user_id = await get_current_user_id(token)
    room = _rooms_db.get(room_id)
    if not room:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Salon non trouvé"
        )

    member_id = f"member_{secrets.token_urlsafe(4)}"
    _room_members_db[f"{room_id}:{user_id}"] = {
        "id": member_id,
        "room_id": room_id,
        "user_id": user_id,
        "role": "member",
        "joined_at": datetime.utcnow()
    }

    # Incrémenter le compteur de membres
    room["member_count"] = room.get("member_count", 1) + 1
    _rooms_db[room_id] = room

    return {"message": "Salon rejoint", "room_id": room_id}