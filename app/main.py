from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager
from app.database import close_redis, get_redis
from app.config import settings
from app.routers import auth, rooms, messages, websocket as ws_router
from app.security import SecurityUtils
from app.services.redis_store import ensure_admin_user


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Gestion du cycle de vie de l'application."""
    # Startup: initialiser la connexion Redis
    redis_client = await get_redis()
    try:
        await redis_client.ping()
        if settings.SEED_ADMIN:
            await ensure_admin_user(redis_client, SecurityUtils.hash_password)
    except Exception as e:
        print(f"Warning: Could not connect to Redis: {e}")
    yield
    # Shutdown: fermer la connexion Redis
    await close_redis()


def create_app() -> FastAPI:
    """Crée l'application FastAPI."""
    app = FastAPI(
        title=settings.APP_NAME,
        description="Chat chiffré de bout en bout - SDV DEV 2026",
        version="1.0.0",
        lifespan=lifespan,
    )

    # Middleware CORS
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Routes d'authentification
    app.include_router(auth.router, tags=["auth"])
    app.include_router(rooms.router, tags=["rooms"])
    app.include_router(messages.router, tags=["messages"])

    # Routes WebSocket
    app.include_router(ws_router.router, tags=["websocket"])

    @app.get("/health")
    async def health_check():
        """Vérification de la santé de l'application."""
        return {"status": "healthy", "service": settings.APP_NAME}

    return app


app = create_app()