from __future__ import annotations

import secrets
from datetime import UTC, datetime, timedelta

from fastapi import HTTPException, Request
from starlette.responses import Response

from app.config import settings
from app.db import mongo

SESSIONS_COLLECTION = "Sessions"
USERS_COLLECTION = "Users"


def origin_allowed(origin: str | None) -> bool:
    if origin is None:
        return False
    return origin in settings.allowed_origins


def set_csrf_cookie(response: Response) -> str:
    token = secrets.token_urlsafe(32)
    response.set_cookie(
        settings.csrf_cookie,
        token,
        max_age=settings.session_ttl_seconds,
        httponly=False,
        secure=settings.cookie_secure,
        samesite="strict",
        path="/",
    )
    return token


def require_csrf(request: Request) -> None:
    origin = request.headers.get("origin", request.headers.get("referer"))
    if not origin_allowed(origin):
        raise HTTPException(status_code=403, detail="Origine non autorisée.")
    header = request.headers.get("x-csrf-token")
    cookie = request.cookies.get(settings.csrf_cookie)
    if not header or not cookie or header != cookie:
        raise HTTPException(status_code=403, detail="Token CSRF invalide.")


async def create_session(user_id: object) -> dict:
    now = datetime.now(UTC)
    return {
        "session_id": secrets.token_urlsafe(32),
        "user_id": user_id,
        "created_at": now,
        "expires_at": now + timedelta(seconds=settings.session_ttl_seconds),
    }


async def get_current_user(request: Request) -> dict:
    session_id = request.cookies.get(settings.session_cookie)
    if not session_id:
        raise HTTPException(status_code=401, detail="Non authentifié.")
    sessions = mongo.db[SESSIONS_COLLECTION]
    session = await sessions.find_one({"session_id": session_id})
    expires_at = session.get("expires_at")
    if expires_at is not None and expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=UTC)
    if session is None or expires_at is None or expires_at < datetime.now(UTC):
        raise HTTPException(status_code=401, detail="Session invalide ou expirée.")
    users = mongo.db[USERS_COLLECTION]
    user = await users.find_one({"_id": session["user_id"]})
    if user is None:
        raise HTTPException(status_code=401, detail="Utilisateur introuvable.")
    user["_session"] = session
    return user