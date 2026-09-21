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
    """Profil public d'un utilisateur : ``{id, username, public_key, created_at,
    display_name, about}``, sinon 404.

    Passé par ``users.to_public`` : ``display_name``/``about`` (profil public
    personnalisable) sont inclus, à ``None`` pour les comptes antérieurs.
    """
    user = users.get_by_username(redis, username)
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")
    return users.to_public(user)
