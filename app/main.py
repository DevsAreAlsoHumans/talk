"""Point d'entrée : assemble l'application FastAPI (API + fichiers statiques du frontend)."""

import logging
from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from redis.asyncio import Redis

from app.config import Settings
from app.errors import register_exception_handlers
from app.realtime import ConnectionManager, EventBus
from app.routers import auth, conversations, friends, health, me, messages, rooms, users, ws
from app.security.csrf import CSRFMiddleware
from app.security.headers import SecurityHeadersMiddleware

FRONTEND_DIR = Path(__file__).resolve().parent.parent / "frontend"


def create_app(settings: Settings | None = None, redis_factory: Callable[[], Redis] | None = None) -> FastAPI:
    """Construit l'application. `redis_factory` permet d'injecter un Redis de test."""
    settings = settings or Settings()
    logging.basicConfig(level=logging.INFO)

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        redis = (
            redis_factory() if redis_factory else Redis.from_url(settings.redis_url, decode_responses=True)
        )
        manager = ConnectionManager()
        bus = EventBus(redis, manager)
        app.state.redis = redis
        app.state.connection_manager = manager
        app.state.event_bus = bus
        await bus.start()
        try:
            yield
        finally:
            await bus.stop()
            await redis.aclose()

    # Documentation interactive désactivée : surface d'attaque en moins (et la CSP la bloquerait).
    app = FastAPI(title="talk", lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)
    app.state.settings = settings

    # Le dernier middleware ajouté est le plus externe : les en-têtes couvrent aussi les rejets CSRF.
    app.add_middleware(CSRFMiddleware, settings=settings)
    app.add_middleware(SecurityHeadersMiddleware)
    register_exception_handlers(app)

    routers = (
        health.router,
        auth.router,
        me.router,
        users.router,
        rooms.router,
        messages.router,
        friends.router,
        conversations.router,
        ws.router,
    )
    for router in routers:
        app.include_router(router)

    # Le frontend est monté en dernier : les routes /api et /ws sont prioritaires.
    app.mount("/", StaticFiles(directory=FRONTEND_DIR, html=True), name="frontend")
    return app
