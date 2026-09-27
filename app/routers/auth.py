from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from app.security import SecurityUtils
from app.models import (
    User, UserCreate, UserLogin, UserResponse, Room, RoomResponse,
    RoomMember, MessageCreate, Message, MessageResponse
)
from app.database import get_redis
import secrets
from datetime import datetime

# OAuth2 scheme
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/login")

router = APIRouter(prefix="/api/auth", tags=["auth"])

# Stockage en mémoire pour l'exemple (à remplacer par Redis/MongoDB)
_users_db = {}
_sessions_db = {}


@router.post("/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
async def register(user_data: UserCreate):
    """Inscrit un nouvel utilisateur."""
    # Vérifier l'unicité de l'email
    for user in _users_db.values():
        if user.get("email") == user_data.email:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Cet email est déjà utilisé"
            )

    # Hash du mot de passe
    hashed_pw = SecurityUtils.hash_password(user_data.password)

    user_id = f"user_{secrets.token_urlsafe(8)}"
    user = {
        "id": user_id,
        "username": user_data.username,
        "email": user_data.email,
        "password_hash": hashed_pw,
        "created_at": datetime.utcnow(),
        "role": "member"
    }
    _users_db[user_id] = user

    return {
        "id": user_id,
        "username": user_data.username,
        "email": user_data.email,
        "created_at": user["created_at"],
        "role": user["role"]
    }


@router.post("/login", response_model=UserResponse)
async def login(login_data: UserLogin):
    """Connecte un utilisateur."""
    # Rechercher l'utilisateur par email
    user = None
    for u in _users_db.values():
        if u.get("email") == login_data.email:
            user = u
            break

    if not user or not SecurityUtils.verify_password(login_data.password, user["password_hash"]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Email ou mot de passe incorrect",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Créer un token d'accès
    access_token = SecurityUtils.create_access_token(
        data={"sub": user["id"], "username": user["username"]}
    )

    # Créer une session
    session_id = SecurityUtils.generate_session_id()
    _sessions_db[session_id] = {
        "user_id": user["id"],
        "created_at": datetime.utcnow()
    }

    return {
        "id": user["id"],
        "username": user["username"],
        "email": user["email"],
        "created_at": user["created_at"],
        "role": user["role"],
        "access_token": access_token
    }


@router.post("/logout")
async def logout():
    """Déconnecte un utilisateur."""
    return {"message": "Déconnecté"}


@router.get("/me", response_model=UserResponse)
async def get_current_user(token: str = Depends(oauth2_scheme)):
    """Récupère l'utilisateur connecté."""
    user_id = SecurityUtils.extract_user_id_from_token(token)
    user = _users_db.get(user_id)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Utilisateur non trouvé"
        )
    return {
        "id": user["id"],
        "username": user["username"],
        "email": user["email"],
        "created_at": user["created_at"],
        "role": user["role"]
    }


@router.get("/csrf-token")
async def get_csrf_token():
    """Génère un token CSRF."""
    return {"csrf_token": SecurityUtils.generate_csrf_token()}