"""Factory de l'application FastAPI : middlewares, routes, static et health.

Le serveur ne voit jamais de texte clair : il ne stocke que du ciphertext,
des nonces et des clés de salon enveloppées. Toutes les erreurs sont génériques
(``{"detail": "..."}``) — aucune stack trace n'est exposée.
"""

from __future__ import annotations

import logging
from pathlib import Path

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from redis import Redis

from app.api.router import api_router
from app.config import settings
from app.db.redis import client_from_url, get_redis
from app.realtime.hub import InProcessHub
from app.realtime.ws import router as ws_router
from app.security.csrf import CSRFMiddleware
from app.security.headers import SecurityHeadersMiddleware

logger = logging.getLogger("talk")  # nom technique conservé (identifiant interne)


def create_app() -> FastAPI:
    """Construit l'application complète (routes API, WS, static, health)."""
    app = FastAPI(title="Télécord", version="0.1.0")
    app.state.redis = client_from_url(settings.REDIS_URL)
    app.state.hub = InProcessHub()

    # Middlewares (ajoutés dans l'ordre : le dernier est le plus externe).
    app.add_middleware(SecurityHeadersMiddleware, cookie_secure=settings.COOKIE_SECURE)
    app.add_middleware(CSRFMiddleware, exclude_paths={"/api/csrf"})

    app.include_router(api_router)
    app.include_router(ws_router)

    @app.get("/api/health")
    def health(redis: Redis = Depends(get_redis)) -> dict[str, str]:
        """Healthcheck : ping Redis, sinon 500 générique."""
        try:
            redis.ping()
        except Exception as exc:  # Redis injoignable → 500 (pas de détail interne)
            raise HTTPException(status_code=500, detail="Redis unavailable") from exc
        return {"status": "ok", "redis": "ok"}

    _register_exception_handlers(app)

    # Frontend vanilla servi à la racine (créé par la tâche frontend).
    frontend_dir = Path(__file__).resolve().parent.parent / "frontend"
    if frontend_dir.is_dir():
        app.mount("/", StaticFiles(directory=frontend_dir, html=True), name="frontend")

    return app


def _register_exception_handlers(app: FastAPI) -> None:
    """Enregistre le handler générique : 500 sans stack trace pour le client."""

    @app.exception_handler(Exception)
    async def generic_exception_handler(request: Request, exc: Exception) -> JSONResponse:
        logger.exception("Unhandled server error on %s", request.url.path)
        return JSONResponse(status_code=500, content={"detail": "Internal server error"})


# Instance par défaut chargée par ``uvicorn app.main:app`` (les tests peuvent
# créer leur propre instance via ``create_app()`` avec un redis de test).
app = create_app()
