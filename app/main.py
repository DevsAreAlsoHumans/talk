from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from app.db.mongo import client as mongo_client
from app.db.mongo import ensure_indexes
from app.db.redis_client import redis_client
from app.routers import auth, friends, notifications, rooms, users, ws


@asynccontextmanager
async def lifespan(_: FastAPI) -> AsyncIterator[None]:
    await ensure_indexes()
    yield
    await redis_client.aclose()
    mongo_client.close()


app = FastAPI(title="Talk", lifespan=lifespan)
app.include_router(auth.router)
app.include_router(users.router)
app.include_router(friends.router)
app.include_router(rooms.router)
app.include_router(notifications.router)
app.include_router(ws.router)
app.mount("/static", StaticFiles(directory="frontend"), name="static")


@app.get("/health")
def health() -> dict[str, str]:
    """Vérifie que l'API répond (utilisé par Docker/CI)."""
    return {"status": "ok"}


@app.get("/")
def index() -> FileResponse:
    """Sert l'application (salons/messages), pour les utilisateurs déjà connectés."""
    return FileResponse("frontend/index.html")


@app.get("/login")
def login_page() -> FileResponse:
    """Page de connexion, séparée de l'inscription."""
    return FileResponse("frontend/login.html")


@app.get("/register")
def register_page() -> FileResponse:
    """Page d'inscription, séparée de la connexion."""
    return FileResponse("frontend/register.html")
