from datetime import datetime, timedelta, timezone

from bson import ObjectId
from fastapi import APIRouter, Depends, HTTPException, Request, status

from app.auth.models import TokenPair, UserCreate, UserLogin, UserResponse
from app.auth.service import (
    create_access_token,
    create_refresh_token,
    decode_access_token,
    hash_password,
    verify_password,
)
from app.config import settings
from app.db import get_db
from app.ratelimit import enforce

router = APIRouter(prefix="/auth", tags=["auth"])


async def get_current_user(request: Request) -> dict:
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing token")
    token = auth_header.split(" ", 1)[1]
    payload = decode_access_token(token)
    if not payload:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired token")
    if not ObjectId.is_valid(payload.get("sub", "")):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token subject")
    db = get_db()
    user = await db.users.find_one({"_id": ObjectId(payload["sub"])})
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found")
    return user


@router.post("/signup", status_code=status.HTTP_201_CREATED, response_model=UserResponse)
async def signup(data: UserCreate, request: Request):
    enforce(request, "signup", settings.rate_limit_signup, settings.rate_limit_signup_window)

    # Honeypot : un humain ne remplit jamais ce champ masqué.
    if data.website.strip():
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Inscription refusée")

    db = get_db()
    existing = await db.users.find_one({"$or": [{"username": data.username}, {"email": data.email}]})
    if existing:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Username or email already taken")
    user_doc = {
        "username": data.username,
        "email": data.email,
        "password_hash": hash_password(data.password),
        "public_key": data.public_key,
        "created_at": datetime.now(timezone.utc),
    }
    result = await db.users.insert_one(user_doc)
    user_doc["_id"] = result.inserted_id
    return UserResponse(
        id=str(user_doc["_id"]),
        username=user_doc["username"],
        email=user_doc["email"],
        public_key=user_doc["public_key"],
        created_at=user_doc["created_at"],
    )


@router.post("/login", response_model=TokenPair)
async def login(data: UserLogin, request: Request):
    enforce(request, "login", settings.rate_limit_login, settings.rate_limit_login_window)

    db = get_db()
    user = await db.users.find_one({"username": data.username})
    if not user or not verify_password(data.password, user["password_hash"]):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")
    access_token = create_access_token({"sub": str(user["_id"])})
    refresh_token = create_refresh_token({"sub": str(user["_id"])})
    await db.refresh_tokens.insert_one(
        {
            "user_id": user["_id"],
            "token": refresh_token,
            "expires_at": datetime.now(timezone.utc) + timedelta(days=settings.jwt_refresh_expire_days),
        }
    )
    return TokenPair(access_token=access_token, refresh_token=refresh_token)


@router.post("/logout")
async def logout(user: dict = Depends(get_current_user)):
    db = get_db()
    await db.refresh_tokens.delete_many({"user_id": user["_id"]})
    return {"detail": "Logged out"}


@router.post("/refresh")
async def refresh(body: dict):
    refresh_token = body.get("refresh_token")
    if not refresh_token or not isinstance(refresh_token, str):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Missing refresh token")
    payload = decode_access_token(refresh_token)
    if not payload or payload.get("type") != "refresh":
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid refresh token")
    db = get_db()
    stored = await db.refresh_tokens.find_one({"token": refresh_token})
    if not stored:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Refresh token revoked")
    new_access = create_access_token({"sub": payload["sub"]})
    return {"access_token": new_access, "token_type": "bearer"}


@router.get("/me", response_model=UserResponse)
async def me(user: dict = Depends(get_current_user)):
    return UserResponse(
        id=str(user["_id"]),
        username=user["username"],
        email=user["email"],
        public_key=user["public_key"],
        created_at=user["created_at"],
    )


@router.get("/users/{username}/public-key")
async def get_public_key(username: str, _user: dict = Depends(get_current_user)):
    db = get_db()
    target = await db.users.find_one({"username": username}, {"public_key": 1, "username": 1})
    if not target:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    return {"id": str(target["_id"]), "username": target["username"], "public_key": target["public_key"]}


@router.delete("/me", status_code=status.HTTP_200_OK)
async def delete_account(user: dict = Depends(get_current_user)):
    """Droit à l'effacement (RGPD art. 17)."""
    db = get_db()
    await db.refresh_tokens.delete_many({"user_id": user["_id"]})
    await db.messages.delete_many({"sender_id": user["_id"]})
    await db.salons.update_many({}, {"$pull": {"members": {"user_id": user["_id"]}}})
    await db.salons.delete_many({"owner_id": user["_id"]})
    await db.users.delete_one({"_id": user["_id"]})
    return {"detail": "Compte et données associées supprimés"}
