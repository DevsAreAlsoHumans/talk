from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from app.security import SecurityUtils
from app.models import (
    UserCreate, UserLogin, UserResponse
)
from app.database import get_redis
from app.config import settings
from app.services.redis_store import encode, get_json
from redis.asyncio import Redis
import secrets
from datetime import datetime

# OAuth2 scheme
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/login")

router = APIRouter(prefix="/api/auth", tags=["auth"])

USER_KEY = "user:{}"
EMAIL_KEY = "user:email:{}"
USERNAME_KEY = "user:username:{}"
SESSION_KEY = "session:{}"


@router.post("/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
async def register(user_data: UserCreate, redis: Redis = Depends(get_redis)):
    """Inscrit un nouvel utilisateur."""
    email_key = EMAIL_KEY.format(user_data.email.lower())
    username_key = USERNAME_KEY.format(user_data.username.lower())
    if await redis.exists(email_key):
        raise HTTPException(status_code=400, detail="Cet email est déjà utilisé")
    if await redis.exists(username_key):
        raise HTTPException(status_code=400, detail="Ce nom d'utilisateur est déjà utilisé")

    # Hash du mot de passe
    hashed_pw = SecurityUtils.hash_password(user_data.password)

    user_id = f"user_{secrets.token_urlsafe(8)}"
    user = {
        "id": user_id,
        "username": user_data.username,
        "email": user_data.email,
        "password_hash": hashed_pw,
        "created_at": datetime.utcnow().isoformat(),
        "role": "member"
    }
    async with redis.pipeline(transaction=True) as pipeline:
        pipeline.set(email_key, user_id, nx=True)
        pipeline.set(username_key, user_id, nx=True)
        pipeline.set(USER_KEY.format(user_id), encode(user))
        results = await pipeline.execute()
    if not results[0] or not results[1]:
        await redis.delete(USER_KEY.format(user_id), email_key)
        raise HTTPException(status_code=400, detail="Utilisateur déjà existant")

    return {
        "id": user_id,
        "username": user_data.username,
        "email": user_data.email,
        "created_at": user["created_at"],
        "role": user["role"]
    }


@router.post("/login", response_model=UserResponse)
async def login(login_data: UserLogin, redis: Redis = Depends(get_redis)):
    """Connecte un utilisateur."""
    # Rechercher l'utilisateur par email
    identifier = login_data.email.strip().lower()
    user_id = await redis.get(EMAIL_KEY.format(identifier))
    if user_id is None:
        user_id = await redis.get(USERNAME_KEY.format(identifier))
    user = await get_json(redis, USER_KEY.format(user_id)) if user_id else None

    if not user or not SecurityUtils.verify_password(login_data.password, user["password_hash"]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Email ou mot de passe incorrect",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Créer un token d'accès
    session_id = SecurityUtils.generate_session_id()
    access_token = SecurityUtils.create_access_token(
        data={"sub": user["id"], "username": user["username"], "sid": session_id}
    )
    await redis.setex(SESSION_KEY.format(session_id), settings.SESSION_COOKIE_MAX_AGE, encode({
        "user_id": user["id"],
        "created_at": datetime.utcnow().isoformat(),
    }))

    return {
        "id": user["id"],
        "username": user["username"],
        "email": user["email"],
        "created_at": user["created_at"],
        "role": user["role"],
        "access_token": access_token
    }


@router.post("/logout")
async def logout(token: str = Depends(oauth2_scheme), redis: Redis = Depends(get_redis)):
    """Déconnecte un utilisateur."""
    payload = SecurityUtils.verify_token(token)
    session_id = payload.get("sid")
    if session_id:
        await redis.delete(SESSION_KEY.format(session_id))
    return {"message": "Déconnecté"}


@router.get("/me", response_model=UserResponse)
async def get_current_user(token: str = Depends(oauth2_scheme), redis: Redis = Depends(get_redis)):
    """Récupère l'utilisateur connecté."""
    user_id = SecurityUtils.extract_user_id_from_token(token)
    user = await get_json(redis, USER_KEY.format(user_id))
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


@router.get("/users/search")
async def search_users(query: str = "", token: str = Depends(oauth2_scheme), redis: Redis = Depends(get_redis)):
    """Recherche des utilisateurs pour les invitations d'espaces."""
    current_user_id = SecurityUtils.extract_user_id_from_token(token)
    normalized_query = query.strip().lower()
    results = []
    async for key in redis.scan_iter(match="user:user_*"):
        user = await get_json(redis, key)
        if not user or user["id"] == current_user_id:
            continue
        if normalized_query and normalized_query not in user["username"].lower() and normalized_query not in user["email"].lower():
            continue
        results.append({"id": user["id"], "username": user["username"], "email": user["email"]})
        if len(results) >= 8:
            break
    return results