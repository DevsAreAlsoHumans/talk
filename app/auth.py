from datetime import UTC, datetime
from typing import Annotated

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerifyMismatchError
from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import BaseModel, Field

from app.config import settings
from app.db import mongo
from app.security import (
    SESSIONS_COLLECTION,
    USERS_COLLECTION,
    create_session,
    get_current_user,
    require_csrf,
    set_csrf_cookie,
)

router = APIRouter(prefix="/api/auth", tags=["auth"])

hasher = PasswordHasher()


async def authenticated_user(request: Request) -> dict:
    return await get_current_user(request)


CurrentUser = Annotated[dict, Depends(authenticated_user)]
Csrf = Annotated[None, Depends(require_csrf)]


class RegisterRequest(BaseModel):
    username: str = Field(min_length=3, max_length=30, pattern=r"^[\w.-]+$")
    email: str = Field(min_length=3, max_length=254, pattern=r"^[\w.+-]+@[\w-]+\.[\w.]+$")
    password: str = Field(min_length=8, max_length=128)
    password_confirm: str = Field(min_length=8, max_length=128)


class LoginRequest(BaseModel):
    username: str = Field(min_length=1, max_length=30)
    password: str = Field(min_length=1, max_length=128)


@router.get("/csrf")
async def csrf_bootstrap(response: Response) -> dict:
    token = set_csrf_cookie(response)
    return {"csrf_token": token}


@router.post("/register", status_code=201)
async def register(
    payload: RegisterRequest,
    response: Response,
    _csrf: Csrf,
) -> dict:
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

    session = await create_session(result.inserted_id)
    await mongo.db[SESSIONS_COLLECTION].insert_one(session)
    response.set_cookie(
        "talk_session",
        session["session_id"],
        max_age=settings.session_ttl_seconds,
        httponly=True,
        secure=settings.cookie_secure,
        samesite="strict",
        path="/",
    )
    set_csrf_cookie(response)

    return {
        "id": str(result.inserted_id),
        "username": user["username"],
        "email": user["email"],
        "redirect": "/chat",
    }


@router.post("/login")
async def login(
    payload: LoginRequest,
    response: Response,
    _csrf: Csrf,
) -> dict:
    users = mongo.db[USERS_COLLECTION]
    user = await users.find_one({"username": payload.username})

    if user is None:
        raise HTTPException(
            status_code=401,
            detail="Nom d'utilisateur ou mot de passe incorrect.",
        )

    try:
        hasher.verify(user["password_hash"], payload.password)
    except (VerifyMismatchError, InvalidHashError):
        raise HTTPException(
            status_code=401,
            detail="Nom d'utilisateur ou mot de passe incorrect.",
        )

    session = await create_session(user["_id"])
    await mongo.db[SESSIONS_COLLECTION].insert_one(session)
    response.set_cookie(
        "talk_session",
        session["session_id"],
        max_age=settings.session_ttl_seconds,
        httponly=True,
        secure=settings.cookie_secure,
        samesite="strict",
        path="/",
    )
    set_csrf_cookie(response)

    return {
        "id": str(user["_id"]),
        "username": user["username"],
        "email": user["email"],
        "redirect": "/chat",
    }


@router.post("/logout")
async def logout(
    request: Request,
    response: Response,
    user: CurrentUser,
    _csrf: Csrf,
) -> dict:
    session_id = request.cookies.get("talk_session")
    await mongo.db[SESSIONS_COLLECTION].delete_one({"session_id": session_id})
    response.delete_cookie("talk_session", path="/")
    response.delete_cookie("talk_csrf_token", path="/")
    return {"ok": True}