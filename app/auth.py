from datetime import UTC, datetime

from argon2 import PasswordHasher
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from app.db import mongo

router = APIRouter(prefix="/api/auth", tags=["auth"])

USERS_COLLECTION = "Users"

hasher = PasswordHasher()


class RegisterRequest(BaseModel):
    username: str = Field(min_length=3, max_length=30)
    email: str = Field(min_length=3, max_length=254)
    password: str = Field(min_length=8, max_length=128)
    password_confirm: str = Field(min_length=8, max_length=128)


@router.post("/register", status_code=201)
async def register(payload: RegisterRequest) -> dict:
    if payload.password != payload.password_confirm:
        raise HTTPException(
            status_code=422,
            detail="Les mots de passe ne correspondent pas.",
        )

    users = mongo.db[USERS_COLLECTION]
    existing = await users.find_one(
        {"$or": [{"username": payload.username}, {"email": payload.email}]},
        projection={"_id": 1},
    )
    if existing is not None:
        raise HTTPException(
            status_code=409,
            detail="Ce nom d'utilisateur ou cet email est déjà utilisé.",
        )

    user = {
        "username": payload.username,
        "email": payload.email,
        "password_hash": hasher.hash(payload.password),
        "created_at": datetime.now(UTC),
    }
    result = await users.insert_one(user)

    return {
        "id": str(result.inserted_id),
        "username": user["username"],
        "email": user["email"],
        "redirect": "/chat",
    }