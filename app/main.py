"""Talk — API FastAPI (backend E2EE).

Règle d'or : ce processeur ne VOIT JAMAIS de texte clair. Il stocke des blobs
opaques et vérifie les sessions, mais le déchiffrement n'existe que coté client.
"""

from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from .config import get_settings
from .db import close_db
from .middleware import SecurityHeadersMiddleware
from .routers import auth, channels, friends, keys, rooms, ws

settings = get_settings()

# Frontend Vanilla (aucune dépendance) : servi ici pour respecter la CSP 'self'.
# Le code source vit dans frontend/ (structure du rendu) et est exposé sous /static.
_FRONTEND_DIR = Path(__file__).resolve().parent.parent / "frontend"


@asynccontextmanager
async def lifespan(_: FastAPI):
    # Aucune connexion DB au boot : connexion lazy (premier accès réel).
    try:
        yield
    finally:
        await close_db()


app = FastAPI(title="Talk", version="0.1.0", lifespan=lifespan, docs_url=None, redoc_url=None)

# CORS : allowlist RESTRICTIVE. Credentials + "*" = accès arbitraire aux cookies.
# Les origines autorisées viennent de l'environnement (TALK_CORS_ORIGINS), vide
# par défaut => pas d'origine tierce, le front est servi par le même hôte.
_cors_origins = settings.cors_origins
app.add_middleware(
    CORSMiddleware,
    allow_origins=_cors_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "DELETE"],
    allow_headers=["Content-Type", "X-CSRF-Token"],  # seul header custom autorisé
    expose_headers=[],
)

# Headers de sécurité posés ensuite (CSP, nosniff, anti-clickjacking...)
app.add_middleware(SecurityHeadersMiddleware)

app.include_router(auth.router)
app.include_router(rooms.router)
app.include_router(channels.router)
app.include_router(keys.router)
app.include_router(friends.router)
app.include_router(ws.router)

# Front : fichiers statiques + entrée racine
if _FRONTEND_DIR.is_dir():
    app.mount("/static", StaticFiles(directory=_FRONTEND_DIR), name="static")
    @app.get("/")
    async def index() -> FileResponse:
        return FileResponse(_FRONTEND_DIR / "index.html")


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok"}
