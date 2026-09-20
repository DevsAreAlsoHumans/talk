"""Authentification : inscription, connexion, déconnexion, session courante, jeton CSRF."""

from fastapi import APIRouter, HTTPException, Request, Response
from starlette.concurrency import run_in_threadpool

from app.config import Settings
from app.deps import (
    AuthDep,
    ConnectionManagerDep,
    RedisDep,
    SessionsDep,
    SettingsDep,
    UsersDep,
    client_ip,
)
from app.schemas import CsrfResponse, LoginRequest, LoginResponse, RegisterRequest, UserPublic, UserSelf
from app.security.csrf import generate_csrf_token
from app.security.passwords import hash_secret, verify_secret
from app.security.rate_limit import is_rate_limited, reset
from app.security.sessions import hash_session_id

router = APIRouter(prefix="/api", tags=["auth"])


def _set_cookie(response: Response, settings: Settings, name: str, value: str) -> None:
    response.set_cookie(
        name,
        value,
        max_age=settings.session_ttl_seconds,
        path="/",
        httponly=True,
        secure=settings.cookie_secure,
        samesite="strict",
    )


def _too_many_requests(window_seconds: int) -> HTTPException:
    return HTTPException(
        status_code=429,
        detail="Trop de tentatives, réessayez plus tard",
        headers={"Retry-After": str(window_seconds)},
    )


@router.get("/csrf", response_model=CsrfResponse)
async def get_csrf_token(request: Request, response: Response, settings: SettingsDep) -> dict[str, str]:
    """Délivre un jeton CSRF lié à la session courante (ou anonyme avant connexion)."""
    session_id = request.cookies.get(settings.session_cookie_name)
    token = generate_csrf_token(settings.secret_key, session_id)
    _set_cookie(response, settings, settings.csrf_cookie_name, token)
    return {"csrf_token": token}


@router.post("/auth/register", status_code=201, response_model=UserPublic)
async def register(
    body: RegisterRequest, request: Request, settings: SettingsDep, redis: RedisDep, users: UsersDep
) -> dict[str, str]:
    if await is_rate_limited(
        redis, f"rl:register:{client_ip(request)}", settings.register_limit, settings.register_window_seconds
    ):
        raise _too_many_requests(settings.register_window_seconds)

    password_hash = await run_in_threadpool(hash_secret, body.auth_secret)
    user = await users.create(
        username=body.username,
        password_hash=password_hash,
        public_key=body.public_key,
        encrypted_private_key=body.encrypted_private_key,
    )
    if user is None:
        raise HTTPException(status_code=409, detail="Nom d'utilisateur indisponible")
    return user


@router.post("/auth/login", response_model=LoginResponse)
async def login(
    body: LoginRequest,
    request: Request,
    response: Response,
    settings: SettingsDep,
    redis: RedisDep,
    users: UsersDep,
    sessions: SessionsDep,
) -> dict:
    ip = client_ip(request)
    account_key = f"rl:login:{ip}:{body.username}"
    ip_limited = await is_rate_limited(
        redis, f"rl:login:{ip}", settings.login_ip_limit, settings.login_window_seconds
    )
    account_limited = await is_rate_limited(
        redis, account_key, settings.login_account_limit, settings.login_window_seconds
    )
    if ip_limited or account_limited:
        raise _too_many_requests(settings.login_window_seconds)

    user = await users.get_by_username(body.username)
    valid = await run_in_threadpool(verify_secret, user["password_hash"] if user else None, body.auth_secret)
    if user is None or not valid:
        raise HTTPException(status_code=401, detail="Identifiants invalides")
    await reset(redis, account_key)

    # Rotation de session : l'ancienne est détruite, une nouvelle est émise (anti-fixation).
    await sessions.destroy(request.cookies.get(settings.session_cookie_name))
    session_id = await sessions.create(user["id"])
    csrf_token = generate_csrf_token(settings.secret_key, session_id)
    _set_cookie(response, settings, settings.session_cookie_name, session_id)
    _set_cookie(response, settings, settings.csrf_cookie_name, csrf_token)
    return {"user": user, "csrf_token": csrf_token}


@router.post("/auth/logout", status_code=204)
async def logout(
    request: Request,
    response: Response,
    settings: SettingsDep,
    sessions: SessionsDep,
    manager: ConnectionManagerDep,
) -> None:
    session_id = request.cookies.get(settings.session_cookie_name)
    if session_id:
        await sessions.destroy(session_id)
        await manager.close_session(hash_session_id(session_id))
    for name in (settings.session_cookie_name, settings.csrf_cookie_name):
        response.delete_cookie(
            name, path="/", secure=settings.cookie_secure, httponly=True, samesite="strict"
        )


@router.get("/auth/me", response_model=UserSelf)
async def me(auth: AuthDep) -> dict[str, str]:
    return auth.user
