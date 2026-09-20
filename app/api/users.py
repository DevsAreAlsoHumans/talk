"""Recherche d'utilisateurs par nom d'utilisateur (profil public).

Utile au client pour récupérer la clé publique d'un membre cible avant un
enveloppement (wrap) de clé de salon.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from redis import Redis

from app.db.redis import get_redis
from app.repositories import users

router = APIRouter(prefix="/users", tags=["users"])


@router.get("/{username}")
def get_user(username: str, redis: Redis = Depends(get_redis)) -> dict:
    """Profil public d'un utilisateur : ``{id, username, public_key}``, sinon 404."""
    user = users.get_by_username(redis, username)
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")
    return {
        "id": user["id"],
        "username": user["username"],
        "public_key": user["public_key"],
    }
