"""Routes d'authentification."""

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from redis import Redis

from app.api.deps import current_user, require_csrf
from app.config import get_settings
from app.db import get_redis
from app.repositories import users
from app.schemas import (
    CsrfResponse,
    LoginRequest,
    MessageResponse,
    RegisterRequest,
    SessionResponse,
    UserPublic,
)
from app.security.csrf import CSRF_COOKIE, issue_csrf_token, set_csrf_cookie
from app.security.passwords import hash_password, verify_password
from app.security.ratelimit import enforce_rate_limit
from app.security.sessions import (
    SESSION_COOKIE,
    clear_session_cookie,
    create_session,
    destroy_session,
    set_session_cookie,
)

router = APIRouter(prefix="/auth", tags=["auth"])

INVALID_LOGIN = HTTPException(
    status_code=status.HTTP_401_UNAUTHORIZED,
    detail="Identifiants invalides.",
)


def _client_key(request: Request) -> str:
    forwarded = request.headers.get("x-forwarded-for")
    ip = forwarded.split(",")[0].strip() if forwarded else (request.client.host or "unknown")
    return f"ratelimit:{ip}"


def _public(user: dict) -> UserPublic:
    """Ne jamais exposer le hash du mot de passe."""
    return UserPublic(id=user["id"], username=user["username"], created_at=user["created_at"])


def _start_session(response: Response, redis: Redis, user: dict) -> SessionResponse:
    session_token = create_session(redis, user["id"])
    csrf_token = issue_csrf_token(redis, session_token)
    set_session_cookie(response, session_token)
    set_csrf_cookie(response, csrf_token)
    return SessionResponse(user=_public(user), csrf_token=csrf_token)


@router.get("/csrf", response_model=CsrfResponse)
def csrf(request: Request, response: Response, redis: Redis = Depends(get_redis)) -> CsrfResponse:
    session_token = request.cookies.get(SESSION_COOKIE)
    token = issue_csrf_token(redis, session_token)
    set_csrf_cookie(response, token)
    return CsrfResponse(csrf_token=token)


@router.post("/register", response_model=SessionResponse, status_code=status.HTTP_201_CREATED)
def register(
    payload: RegisterRequest,
    request: Request,
    response: Response,
    redis: Redis = Depends(get_redis),
    _csrf: None = Depends(require_csrf),
) -> SessionResponse:
    settings = get_settings()
    enforce_rate_limit(
        redis,
        f"ratelimit:register:{_client_key(request)}",
        limit=settings.rate_limit_register_max,
        window=settings.rate_limit_register_window,
    )
    user = users.create_user(redis, payload.username, hash_password(payload.password))
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Ce pseudo est deja pris.",
        )
    return _start_session(response, redis, user)


@router.post("/login", response_model=SessionResponse)
def login(
    payload: LoginRequest,
    request: Request,
    response: Response,
    redis: Redis = Depends(get_redis),
    _csrf: None = Depends(require_csrf),
) -> SessionResponse:
    settings = get_settings()
    enforce_rate_limit(
        redis,
        f"ratelimit:login:{_client_key(request)}",
        limit=settings.rate_limit_login_max,
        window=settings.rate_limit_login_window,
    )
    user = users.get_by_username(redis, payload.username)
    stored_hash = user["password_hash"] if user else "scrypt$16384$8$1$00$00"
    # Verification systematique pour ne pas reveler l'existence du compte.
    if not verify_password(payload.password, stored_hash) or user is None:
        raise INVALID_LOGIN
    return _start_session(response, redis, user)


@router.post("/logout", response_model=MessageResponse, dependencies=[Depends(require_csrf)])
def logout(
    request: Request,
    response: Response,
    redis: Redis = Depends(get_redis),
    _user: dict = Depends(current_user),
) -> MessageResponse:
    destroy_session(redis, request.cookies.get(SESSION_COOKIE))
    clear_session_cookie(response)
    response.delete_cookie(CSRF_COOKIE, path="/")
    return MessageResponse(detail="Deconnexion effectuee.")


@router.get("/me", response_model=UserPublic)
def me(_user: dict = Depends(current_user)) -> UserPublic:
    return _public(_user)
