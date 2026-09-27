"""Application : point d'entree FastAPI."""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.auth import router as auth_router
from app.api.keys import router as keys_router
from app.api.messages import router as messages_router
from app.api.salons import router as salons_router
from app.config import get_settings
from app.security.headers import SecurityHeadersMiddleware
from app.web import mount_static
from app.web import router as web_router
from app.ws import router as ws_router


def create_app() -> FastAPI:
    settings = get_settings()
    app = FastAPI(
        title="talk",
        version="0.1.0",
        debug=settings.debug,
    )
    app.add_middleware(SecurityHeadersMiddleware)
    if settings.cors_origins:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=settings.cors_origins,
            allow_credentials=True,
            allow_methods=["GET", "POST", "PATCH", "DELETE", "PUT"],
            allow_headers=["Content-Type", "X-CSRF-Token"],
        )
    app.include_router(auth_router)
    app.include_router(salons_router)
    app.include_router(keys_router)
    app.include_router(messages_router)
    app.include_router(web_router)
    app.include_router(ws_router)
    mount_static(app)

    @app.get("/health", tags=["system"])
    async def health() -> dict[str, str]:
        return {"status": "ok", "app": settings.app_name}

    return app


app = create_app()
