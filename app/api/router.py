"""Router API central : préfixe global ``/api`` sur tous les sous-routers."""

from fastapi import APIRouter

from app.api import auth, csrf, messages, rooms, users

api_router = APIRouter(prefix="/api")

api_router.include_router(csrf.router)
api_router.include_router(auth.me_router)
api_router.include_router(auth.router)
api_router.include_router(rooms.router)
api_router.include_router(messages.router)
api_router.include_router(users.router)


__all__ = ["api_router"]
