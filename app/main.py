from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.middleware.base import BaseHTTPMiddleware

from app.analytics import router as analytics_router
from app.auth.router import router as auth_router
from app.config import settings
from app.db import close_db, connect_db
from app.messages.router import router as messages_router
from app.salons.router import router as salons_router
from app.security import csrf_middleware

FRONTEND_DIR = Path(__file__).resolve().parent.parent / "frontend"


@asynccontextmanager
async def lifespan(app: FastAPI):
    await connect_db()
    yield
    await close_db()


app = FastAPI(
    title=settings.app_name,
    description=settings.app_tagline,
    version="2.0.0",
    lifespan=lifespan,
)

app.add_middleware(BaseHTTPMiddleware, dispatch=csrf_middleware)


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=(), interest-cohort=()"
    response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self'; "
        "style-src 'self'; "
        "img-src 'self' data:; "
        "font-src 'self'; "
        "connect-src 'self' ws: wss:; "
        "frame-ancestors 'none'; "
        "base-uri 'self'; "
        "form-action 'self'"
    )
    return response


app.include_router(auth_router)
app.include_router(salons_router)
app.include_router(messages_router)
app.include_router(analytics_router)


@app.get("/health", include_in_schema=False)
async def health():
    return {"status": "ok", "app": settings.app_name}


# Le montage statique ci-dessous capture tout ce qui n'a pas été résolu avant
# lui, y compris les URL d'API mal orthographiées. Ces routes filet garantissent
# qu'un client d'API reçoit du JSON, jamais la page HTML 404.
for _prefix in ("auth", "salons", "api"):

    @app.api_route(
        f"/{_prefix}/{{rest:path}}",
        methods=["GET", "POST", "PUT", "PATCH", "DELETE"],
        include_in_schema=False,
    )
    async def api_catch_all(rest: str):
        raise StarletteHTTPException(status_code=404, detail="Endpoint introuvable")


@app.exception_handler(StarletteHTTPException)
async def not_found_handler(request: Request, exc: StarletteHTTPException):
    """Sert la page 404 personnalisée aux navigateurs, du JSON à l'API."""
    if exc.status_code == 404:
        accepts_html = "text/html" in request.headers.get("accept", "")
        page = FRONTEND_DIR / "404.html"
        if accepts_html and page.is_file():
            return FileResponse(page, status_code=404, media_type="text/html")
    return JSONResponse(status_code=exc.status_code, content={"detail": exc.detail}, headers=exc.headers)


if FRONTEND_DIR.is_dir():
    app.mount("/", StaticFiles(directory=str(FRONTEND_DIR), html=True), name="frontend")
