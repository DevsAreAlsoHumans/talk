"""Dépendances partagées des routers API (auth, contrôles d'accès salons)."""

from __future__ import annotations

from fastapi import Depends, HTTPException, Request
from redis import Redis

from app.db.redis import get_redis
from app.repositories import rooms, users
from app.security.sessions import get_session


def get_current_user(request: Request, redis: Redis = Depends(get_redis)) -> dict:
    """Authentifie l'appelant via le cookie de session.

    Renvoie l'utilisateur complet (enregistrement interne), ou 401 si le
    cookie est absent, invalide ou rattaché à un utilisateur inconnu.
    """
    session = get_session(redis, request)
    if session is None or not session.get("user_id"):
        raise HTTPException(status_code=401, detail="Authentication required")
    user = users.get_by_id(redis, session["user_id"])
    if user is None:
        raise HTTPException(status_code=401, detail="Authentication required")
    return user


def get_room_or_404(redis: Redis, room_id: str) -> dict:
    """Renvoie le salon ou lève une 404 générique."""
    room = rooms.get_room(redis, room_id)
    if room is None:
        raise HTTPException(status_code=404, detail="Room not found")
    return room


def require_member(redis: Redis, room_id: str, user_id: str) -> None:
    """Exige l'appartenance au salon, sinon 403 (accès interdit)."""
    if not rooms.is_member(redis, room_id, user_id):
        raise HTTPException(status_code=403, detail="Not a member of this room")


def client_ip(request: Request) -> str:
    """Adresse IP du client (pour le rate-limit login)."""
    return request.client.host if request.client else "unknown"
