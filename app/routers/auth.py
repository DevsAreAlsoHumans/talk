import random
from datetime import UTC, datetime
from typing import Any

from bson import ObjectId
from fastapi import APIRouter, Cookie, Depends, HTTPException, Response, status
from pymongo.errors import DuplicateKeyError

from app.config import settings
from app.db.mongo import db
from app.models.user import UserLogin, UserPublic, UserRegister
from app.security.passwords import hash_password, validate_password_strength, verify_password
from app.security.sessions import (
    CSRF_COOKIE_NAME,
    SESSION_COOKIE_NAME,
    create_session,
    delete_session,
    get_current_user_id,
    require_csrf,
)

router = APIRouter(prefix="/auth", tags=["auth"])

_DISCRIMINATOR_ATTEMPTS = 20


def _to_public(document: dict[str, Any]) -> UserPublic:
    return UserPublic(
        id=str(document["_id"]),
        username=document["username"],
        discriminator=document["discriminator"],
        email=document["email"],
    )


def _set_session_cookies(response: Response, session_id: str, csrf_token: str) -> None:
    response.set_cookie(
        SESSION_COOKIE_NAME,
        session_id,
        httponly=True,
        secure=settings.cookie_secure,
        samesite="lax",
        max_age=settings.session_ttl_seconds,
    )
    response.set_cookie(
        CSRF_COOKIE_NAME,
        csrf_token,
        httponly=False,
        secure=settings.cookie_secure,
        samesite="lax",
        max_age=settings.session_ttl_seconds,
    )


@router.post("/register", response_model=UserPublic, status_code=status.HTTP_201_CREATED)
async def register(payload: UserRegister, response: Response) -> UserPublic:
    """Crée un compte, attribue un discriminant unique et ouvre une session (auto-login)."""
    error = validate_password_strength(payload.password)
    if error:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=error)

    document: dict[str, Any] = {
        "username": payload.username,
        "username_lower": payload.username.lower(),
        "email": payload.email,
        "password_hash": hash_password(payload.password),
        "created_at": datetime.now(UTC),
    }

    for _ in range(_DISCRIMINATOR_ATTEMPTS):
        document["discriminator"] = f"{random.randint(1, 9999):04d}"
        try:
            result = await db.users.insert_one(document)
        except DuplicateKeyError as exc:
            if "email" in (exc.details or {}).get("keyPattern", {}):
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT, detail="Cet email est déjà utilisé."
                ) from exc
            continue  # collision sur (pseudo, discriminant) : on retire un autre discriminant
        else:
            document["_id"] = result.inserted_id
            break
    else:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Impossible d'attribuer un discriminant pour ce pseudo, réessayez.",
        )

    session_id, csrf_token = await create_session(str(document["_id"]))
    _set_session_cookies(response, session_id, csrf_token)
    return _to_public(document)


@router.post("/login", response_model=UserPublic)
async def login(payload: UserLogin, response: Response) -> UserPublic:
    """Authentifie par email + mot de passe et ouvre une session."""
    document = await db.users.find_one({"email": payload.email})
    if document is None or not verify_password(payload.password, document["password_hash"]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Email ou mot de passe invalide."
        )

    session_id, csrf_token = await create_session(str(document["_id"]))
    _set_session_cookies(response, session_id, csrf_token)
    return _to_public(document)


@router.post(
    "/logout", status_code=status.HTTP_204_NO_CONTENT, dependencies=[Depends(require_csrf)]
)
async def logout(
    response: Response,
    session_id: str | None = Cookie(default=None, alias=SESSION_COOKIE_NAME),
) -> None:
    """Ferme la session courante (nécessite le jeton CSRF)."""
    if session_id:
        await delete_session(session_id)
    response.delete_cookie(SESSION_COOKIE_NAME)
    response.delete_cookie(CSRF_COOKIE_NAME)


@router.get("/me", response_model=UserPublic)
async def me(user_id: str = Depends(get_current_user_id)) -> UserPublic:
    """Renvoie l'utilisateur actuellement connecté."""
    document = await db.users.find_one({"_id": ObjectId(user_id)})
    if document is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Utilisateur introuvable."
        )
    return _to_public(document)
