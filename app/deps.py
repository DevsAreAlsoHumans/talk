"""Dépendances FastAPI : accès à Redis, aux réglages et à l'utilisateur authentifié."""

from dataclasses import dataclass
from typing import Annotated

from fastapi import Depends, HTTPException, Request
from redis.asyncio import Redis

from app.config import Settings
from app.realtime import ConnectionManager, EventBus
from app.repositories.messages import MessageRepository
from app.repositories.rooms import RoomRepository
from app.repositories.users import UserRepository
from app.security.sessions import SessionStore


def get_settings(request: Request) -> Settings:
    return request.app.state.settings


def get_redis(request: Request) -> Redis:
    return request.app.state.redis


def get_event_bus(request: Request) -> EventBus:
    return request.app.state.event_bus


def get_connection_manager(request: Request) -> ConnectionManager:
    return request.app.state.connection_manager


SettingsDep = Annotated[Settings, Depends(get_settings)]
RedisDep = Annotated[Redis, Depends(get_redis)]
EventBusDep = Annotated[EventBus, Depends(get_event_bus)]
ConnectionManagerDep = Annotated[ConnectionManager, Depends(get_connection_manager)]


def get_users(redis: RedisDep) -> UserRepository:
    return UserRepository(redis)


def get_rooms(redis: RedisDep) -> RoomRepository:
    return RoomRepository(redis)


def get_messages(redis: RedisDep) -> MessageRepository:
    return MessageRepository(redis)


def get_sessions(redis: RedisDep, settings: SettingsDep) -> SessionStore:
    return SessionStore(redis, settings.session_ttl_seconds)


UsersDep = Annotated[UserRepository, Depends(get_users)]
RoomsDep = Annotated[RoomRepository, Depends(get_rooms)]
MessagesDep = Annotated[MessageRepository, Depends(get_messages)]
SessionsDep = Annotated[SessionStore, Depends(get_sessions)]


@dataclass(frozen=True)
class AuthContext:
    user: dict[str, str]
    session_id: str


async def require_user(
    request: Request, settings: SettingsDep, sessions: SessionsDep, users: UsersDep
) -> AuthContext:
    """Exige une session valide ; la même réponse générique est renvoyée dans tous les cas d'échec."""
    session_id = request.cookies.get(settings.session_cookie_name)
    user_id = await sessions.get_user_id(session_id)
    user = await users.get(user_id) if user_id else None
    if user is None or session_id is None:
        raise HTTPException(status_code=401, detail="Non authentifié")
    return AuthContext(user=user, session_id=session_id)


AuthDep = Annotated[AuthContext, Depends(require_user)]


def client_ip(request: Request) -> str:
    return request.client.host if request.client else "inconnu"
