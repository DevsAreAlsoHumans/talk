import time
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from fastapi.concurrency import run_in_threadpool

from app.api.common import enforce_rate_limit
from app.config import Settings
from app.dependencies import (
    get_current_user,
    get_settings,
    get_store,
    require_csrf,
)
from app.schemas import LoginRequest, RegisterRequest
from app.security import (
    generate_token,
    hash_password,
    hash_token,
    verify_password_or_dummy,
)
from app.storage import (
    RedisStore,
    UsernameAlreadyExistsError,
)

router = APIRouter(prefix="/api/auth", tags=["authentification"])


async def _user_payload(store: RedisStore, user: dict[str, Any]) -> dict[str, Any]:
    return {**user, "identity_keys": await store.list_identity_keys(user["id"])}


async def _start_session(
    response: Response,
    store: RedisStore,
    settings: Settings,
    user_id: str,
) -> str:
    session_token = generate_token(48)
    csrf_token = generate_token(32)
    expires_at = int(time.time()) + settings.session_ttl_seconds
    await store.create_session(
        token_hash=hash_token(session_token),
        user_id=user_id,
        csrf_token=csrf_token,
        expires_at=expires_at,
    )
    response.set_cookie(
        key=settings.session_cookie_name,
        value=session_token,
        max_age=settings.session_ttl_seconds,
        httponly=True,
        secure=settings.cookie_secure,
        samesite="strict",
        path="/",
    )
    response.set_cookie(
        key=settings.csrf_cookie_name,
        value=csrf_token,
        max_age=settings.csrf_ttl_seconds,
        httponly=True,
        secure=settings.cookie_secure,
        samesite="strict",
        path="/",
    )
    return csrf_token


@router.get("/csrf", summary="Obtenir un jeton CSRF")
async def csrf_token(
    response: Response,
    settings: Settings = Depends(get_settings),
) -> dict[str, str]:
    token = generate_token(32)
    response.set_cookie(
        key=settings.csrf_cookie_name,
        value=token,
        max_age=settings.csrf_ttl_seconds,
        httponly=True,
        secure=settings.cookie_secure,
        samesite="strict",
        path="/",
    )
    return {"csrf_token": token}


@router.post(
    "/register",
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require_csrf)],
    summary="Créer un compte",
)
async def register(
    payload: RegisterRequest,
    request: Request,
    response: Response,
    settings: Settings = Depends(get_settings),
    store: RedisStore = Depends(get_store),
) -> dict[str, Any]:
    await enforce_rate_limit(
        request,
        store,
        settings,
        scope="register",
        limit=settings.registration_rate_limit,
        window_seconds=settings.registration_rate_window,
    )
    password_hash = await run_in_threadpool(hash_password, payload.password)
    try:
        user = await store.register_user(
            username=payload.username,
            display_name=payload.display_name,
            password_hash=password_hash,
            identity_key=payload.identity_key.model_dump(mode="json"),
        )
    except UsernameAlreadyExistsError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Ce nom d'utilisateur est déjà utilisé",
        ) from exc

    csrf_token_value = await _start_session(response, store, settings, user["id"])
    return {
        "user": await _user_payload(store, user),
        "csrf_token": csrf_token_value,
    }


@router.post(
    "/login",
    dependencies=[Depends(require_csrf)],
    summary="Ouvrir une session",
)
async def login(
    payload: LoginRequest,
    request: Request,
    response: Response,
    settings: Settings = Depends(get_settings),
    store: RedisStore = Depends(get_store),
) -> dict[str, Any]:
    await enforce_rate_limit(
        request,
        store,
        settings,
        scope="login",
        limit=settings.login_rate_limit,
        window_seconds=settings.login_rate_window,
    )
    credentials = await store.get_user_by_username(payload.username)
    user = await store.get_user(credentials["id"]) if credentials else None
    password_hash = credentials.get("password_hash") if credentials else None
    password_valid = await run_in_threadpool(
        verify_password_or_dummy, password_hash, payload.password
    )
    if user is None or not password_valid:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Identifiants incorrects",
        )

    csrf_token_value = await _start_session(response, store, settings, user["id"])
    return {
        "user": await _user_payload(store, user),
        "csrf_token": csrf_token_value,
    }


@router.get("/me", summary="Obtenir la session courante")
async def current_session(
    user: dict[str, Any] = Depends(get_current_user),
    store: RedisStore = Depends(get_store),
) -> dict[str, Any]:
    return {"user": await _user_payload(store, user)}


@router.post(
    "/logout",
    dependencies=[Depends(require_csrf)],
    summary="Fermer la session",
)
async def logout(
    request: Request,
    response: Response,
    settings: Settings = Depends(get_settings),
    store: RedisStore = Depends(get_store),
    user: dict[str, Any] = Depends(get_current_user),
) -> dict[str, bool]:
    token = request.cookies.get(settings.session_cookie_name)
    if token:
        await store.delete_session(hash_token(token))
    response.delete_cookie(settings.session_cookie_name, path="/")
    response.delete_cookie(settings.csrf_cookie_name, path="/")
    return {"ok": True}
