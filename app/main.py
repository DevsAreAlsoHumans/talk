from contextlib import asynccontextmanager
from pathlib import Path
from typing import Dict, Optional

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from redis.asyncio import Redis
from starlette.middleware.trustedhost import TrustedHostMiddleware
from starlette.exceptions import HTTPException as StarletteHTTPException

from app.api import auth, messages, rooms, users, websocket
from app.config import Settings, get_settings
from app.realtime import ConnectionManager
from app.storage import RedisStore

CSP = (
    "default-src 'self'; "
    "script-src 'self'; "
    "style-src 'self'; "
    "img-src 'self' data:; "
    "connect-src 'self' ws: wss:; "
    "font-src 'self'; "
    "object-src 'none'; "
    "base-uri 'none'; "
    "frame-ancestors 'none'; "
    "form-action 'self'"
)


def create_app(
    settings: Optional[Settings] = None,
    redis_client: Optional[Redis] = None,
) -> FastAPI:
    app_settings = settings or get_settings()
    owns_redis = redis_client is None

    @asynccontextmanager
    async def lifespan(application: FastAPI):
        application.state.redis = redis_client or Redis.from_url(
            app_settings.redis_url,
            encoding="utf-8",
            decode_responses=True,
            health_check_interval=30,
        )
        application.state.store = RedisStore(application.state.redis)
        application.state.manager = ConnectionManager()
        yield
        if owns_redis:
            await application.state.redis.aclose()

    docs_url = "/docs" if app_settings.docs_enabled and not app_settings.is_production else None
    openapi_url = (
        "/openapi.json"
        if app_settings.docs_enabled and not app_settings.is_production
        else None
    )
    application = FastAPI(
        title="Talk",
        description="Messagerie de salon avec chiffrement de bout en bout côté client.",
        version="0.1.0",
        docs_url=docs_url,
        redoc_url=None,
        openapi_url=openapi_url,
        lifespan=lifespan,
    )
    application.state.settings = app_settings
    application.state.manager = ConnectionManager()

    application.add_middleware(
        CORSMiddleware,
        allow_origins=app_settings.origin_list,
        allow_credentials=True,
        allow_methods=["GET", "POST", "OPTIONS"],
        allow_headers=["Content-Type", "X-CSRF-Token"],
        max_age=600,
    )
    application.add_middleware(
        TrustedHostMiddleware,
        allowed_hosts=app_settings.host_list,
    )

    @application.middleware("http")
    async def security_headers(request: Request, call_next):
        response = await call_next(request)
        response.headers["Content-Security-Policy"] = CSP
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Permissions-Policy"] = (
            "camera=(), microphone=(), geolocation=(), payment=(), usb=()"
        )
        response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
        response.headers["Cross-Origin-Resource-Policy"] = "same-origin"
        if request.url.path.startswith("/api"):
            response.headers["Cache-Control"] = "no-store"
        if app_settings.is_production:
            response.headers["Strict-Transport-Security"] = (
                "max-age=31536000; includeSubDomains"
            )
        return response

    @application.exception_handler(RequestValidationError)
    async def validation_error_handler(
        request: Request, exc: RequestValidationError
    ) -> JSONResponse:
        details = []
        for error in exc.errors():
            location = ".".join(str(part) for part in error.get("loc", ()))
            details.append(
                {
                    "field": location,
                    "message": error.get("msg", "Valeur invalide"),
                    "type": error.get("type", "validation_error"),
                }
            )
        return JSONResponse(
            status_code=422,
            content={
                "error": {
                    "code": "validation_error",
                    "message": "Les données envoyées sont invalides",
                },
                "details": details,
            },
        )

    @application.exception_handler(StarletteHTTPException)
    async def http_error_handler(
        request: Request, exc: StarletteHTTPException
    ) -> JSONResponse:
        code_by_status = {
            400: "bad_request",
            401: "authentication_required",
            403: "forbidden",
            404: "not_found",
            409: "conflict",
            422: "validation_error",
            429: "rate_limit_exceeded",
        }
        return JSONResponse(
            status_code=exc.status_code,
            headers=getattr(exc, "headers", None),
            content={
                "error": {
                    "code": code_by_status.get(exc.status_code, "http_error"),
                    "message": str(exc.detail),
                }
            },
        )

    @application.get("/api/health", tags=["système"])
    async def health(request: Request) -> Dict[str, str]:
        healthy = await request.app.state.store.ping()
        if not healthy:
            return JSONResponse(status_code=503, content={"status": "unavailable"})
        return {"status": "ok"}

    application.include_router(auth.router)
    application.include_router(users.router)
    application.include_router(rooms.router)
    application.include_router(messages.router)
    application.include_router(websocket.router)

    frontend_directory = Path(app_settings.frontend_directory)
    assets_directory = frontend_directory / "assets"
    scripts_directory = frontend_directory / "js"
    if assets_directory.is_dir():
        application.mount(
            "/assets", StaticFiles(directory=str(assets_directory)), name="assets"
        )
    if scripts_directory.is_dir():
        application.mount(
            "/js", StaticFiles(directory=str(scripts_directory)), name="scripts"
        )

    @application.get("/", include_in_schema=False)
    async def frontend() -> FileResponse:
        return FileResponse(str(frontend_directory / "index.html"))

    @application.get("/styles.css", include_in_schema=False)
    async def stylesheet() -> FileResponse:
        return FileResponse(str(frontend_directory / "assets" / "styles.css"))

    return application


app = create_app()
