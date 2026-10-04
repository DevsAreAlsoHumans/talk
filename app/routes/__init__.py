"""Toutes les routes de l'API, regroupées sous /api."""

from fastapi import APIRouter

from app.routes import accounts, messages, servers

router = APIRouter(prefix="/api")
router.include_router(accounts.router)
router.include_router(servers.router)
router.include_router(messages.router)
