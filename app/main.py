"""Point d'entrée de Talk : crée l'application et branche le reste."""

from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from app.database import lifespan
from app.routes import router
from app.security import SECURITY_HEADERS

FRONTEND = Path(__file__).resolve().parent.parent / "frontend"

# Pas de page /docs, et le front est servi dans /static
app = FastAPI(title="Talk", docs_url=None, redoc_url=None, openapi_url=None, lifespan=lifespan)
app.mount("/static", StaticFiles(directory=FRONTEND), name="static")
app.include_router(router)


# Headers de sécurité ajoutés sur toutes les réponses
@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers.update(SECURITY_HEADERS)
    return response


# Données invalides : on ne renvoie pas le détail (pas de fuite d'info)
@app.exception_handler(RequestValidationError)
async def invalid_input(request: Request, error: RequestValidationError):
    return JSONResponse({"detail": "Données invalides"}, status_code=422)


# Erreur imprévue : message générique, jamais la stack trace
@app.exception_handler(Exception)
async def server_error(request: Request, error: Exception):
    return JSONResponse({"detail": "Erreur interne"}, status_code=500)


# Page d'accueil = le front
@app.get("/")
async def home():
    return FileResponse(FRONTEND / "index.html")
