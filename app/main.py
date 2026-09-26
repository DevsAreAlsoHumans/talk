from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from app.auth import router as auth_router
from app.chat import router as chat_router
from app.config import settings
from app.db import mongo

FRONTEND_DIR = Path(__file__).resolve().parents[1] / "frontend"


@asynccontextmanager
async def lifespan(app: FastAPI):
    await mongo.connect()
    yield
    await mongo.close()


app = FastAPI(title="talk", lifespan=lifespan)


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    # Empêche le rendu dans une iframe (clickjacking).
    response.headers["X-Frame-Options"] = "DENY"
    # Interdit au navigateur de deviner un type MIME différent de celui
    # annoncé, ce qui bloque certaines injections de script.
    response.headers["X-Content-Type-Options"] = "nosniff"
    # N'envoie jamais l'URL de référence à un site tiers.
    response.headers["Referrer-Policy"] = "no-referrer"
    # Ni la page ni l'API ne doivent être conservées en cache.
    response.headers["Cache-Control"] = "no-store"
    # Politique de sécurité du contenu : aucun script ni style externe,
    # ce qui empêche l'exécution de code injecté par un message.
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; script-src 'self'; style-src 'self'; "
        "img-src 'self' data:; connect-src 'self'; form-action 'self'"
    )
    # HSTS : uniquement si activé explicitement (défaut 0), car l'en-tête
    # n'a d'effet que sur une réponse HTTPS.
    if settings.hsts_max_age > 0:
        response.headers["Strict-Transport-Security"] = (
            f"max-age={settings.hsts_max_age}; includeSubDomains"
        )
    return response


app.include_router(auth_router)
app.include_router(chat_router)


@app.get("/api/status")
async def root():
    return {"status": "ok", "service": "talk"}


@app.get("/health")
async def health():
    await mongo.ping()
    return {"status": "healthy", "database": "mongodb"}


@app.get("/chat")
async def chat_page():
    return FileResponse(FRONTEND_DIR / "chat.html")


if FRONTEND_DIR.is_dir():
    app.mount("/", StaticFiles(directory=FRONTEND_DIR, html=True), name="frontend")