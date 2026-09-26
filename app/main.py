"""Point d'entrée FastAPI de Talk.

Étape 2 : authentification (inscription, connexion, sessions, CSRF, en-têtes de
sécurité) et point d'entrée WebSocket authentifié par cookie.

Ordre d'enregistrement impératif : le frontend est monté sur `/`, un chemin
qui correspond à tout. Toute route déclarée *après* ce montage serait
inatteignable, car le premier correspondant l'emporte.
"""

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles

from app import db
from app.config import get_settings
from app.middleware import SecurityHeadersMiddleware
from app.routers import auth

FRONTEND_DIR = Path(__file__).resolve().parent.parent / "frontend"


@asynccontextmanager
async def lifespan(_: FastAPI) -> AsyncIterator[None]:
    settings = get_settings()
    await db.ensure_indexes(db.get_client()[settings.mongo_db_name])
    yield
    await db.close_client()


app = FastAPI(
    title="Talk",
    version="0.1.0",
    description="Application de discussion chiffrée de bout en bout.",
    lifespan=lifespan,
)

app.add_middleware(SecurityHeadersMiddleware)

# Avant le montage du frontend sur "/" : voir la note d'ordre en tête de module.
app.include_router(auth.router)


@app.get("/health", tags=["santé"])
def health() -> dict[str, str]:
    """Retourne l'état de l'application."""
    return {"status": "ok"}


# Le frontend est servi par FastAPI : https://localhost:8000/
if FRONTEND_DIR.is_dir():
    app.mount("/", StaticFiles(directory=FRONTEND_DIR, html=True), name="frontend")
