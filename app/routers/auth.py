import asyncio
import random
import secrets
from datetime import UTC, datetime
from typing import Any

from bson import ObjectId
from fastapi import APIRouter, Cookie, Depends, HTTPException, Response, status
from pymongo.errors import DuplicateKeyError

from app.config import settings
from app.db.mongo import db
from app.db.redis_client import redis_client
from app.models.auth import (
    ForgotPasswordRequest,
    LoginResult,
    ResetPasswordRequest,
    TotpCodeInput,
    TotpLoginVerify,
    TotpSetupResult,
)
from app.models.user import UserLogin, UserPublic, UserRegister
from app.security.brute_force import is_locked, record_failed_attempt, reset_attempts
from app.security.passwords import hash_password, validate_password_strength, verify_password
from app.security.sessions import (
    CSRF_COOKIE_NAME,
    SESSION_COOKIE_NAME,
    create_session,
    delete_session,
    get_current_user_id,
    require_csrf,
)
from app.security.totp import (
    consume_pending_login,
    create_pending_login,
    generate_secret,
    get_pending_login,
    totp_uri,
    verify_code,
)
from app.services.mail import send_mail

router = APIRouter(prefix="/auth", tags=["auth"])

_DISCRIMINATOR_ATTEMPTS = 20
_PASSWORD_RESET_TTL_SECONDS = 30 * 60
_PASSWORD_RESET_PREFIX = "password_reset:"


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


async def _get_user_or_401(user_id: str) -> dict[str, Any]:
    document = await db.users.find_one({"_id": ObjectId(user_id)})
    if document is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Utilisateur introuvable."
        )
    return document


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
    return UserPublic.from_document(document)


@router.post("/login", response_model=LoginResult)
async def login(payload: UserLogin, response: Response) -> LoginResult:
    """Authentifie par email + mot de passe ; renvoie un jeton d'attente si la 2FA est active."""
    document = await db.users.find_one({"email": payload.email})
    if document is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Email ou mot de passe invalide."
        )

    user_id = str(document["_id"])
    if await is_locked(user_id):
        raise HTTPException(
            status_code=status.HTTP_423_LOCKED,
            detail="Compte temporairement verrouillé après plusieurs échecs. Réessaie plus tard.",
        )

    if not verify_password(payload.password, document["password_hash"]):
        just_locked = await record_failed_attempt(user_id)
        if just_locked:
            await asyncio.to_thread(
                send_mail,
                document["email"],
                "Alerte de securite - compte verrouille",
                "Ton compte Talk a ete verrouille temporairement (15 minutes) apres "
                "trois tentatives de connexion echouees. Si ce n'etait pas toi, "
                "change ton mot de passe des que possible.",
            )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Email ou mot de passe invalide."
        )

    await reset_attempts(user_id)

    if document.get("totp_secret"):
        pending_token = await create_pending_login(user_id)
        return LoginResult(totp_required=True, pending_token=pending_token)

    session_id, csrf_token = await create_session(user_id)
    _set_session_cookies(response, session_id, csrf_token)
    return LoginResult(totp_required=False, user=UserPublic.from_document(document))


@router.post("/2fa/verify", response_model=UserPublic)
async def verify_totp_login(payload: TotpLoginVerify, response: Response) -> UserPublic:
    """Termine une connexion en attente de code 2FA."""
    user_id = await get_pending_login(payload.pending_token)
    if user_id is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Jeton de connexion invalide/expiré."
        )

    document = await _get_user_or_401(user_id)
    secret = document.get("totp_secret")
    if not secret or not verify_code(secret, payload.code):
        # Code invalide : le jeton reste utilisable pour un nouvel essai (pas de suppression).
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Code invalide.")

    await consume_pending_login(payload.pending_token)
    session_id, csrf_token = await create_session(user_id)
    _set_session_cookies(response, session_id, csrf_token)
    return UserPublic.from_document(document)


@router.post(
    "/2fa/setup", response_model=TotpSetupResult, dependencies=[Depends(require_csrf)]
)
async def setup_totp(user_id: str = Depends(get_current_user_id)) -> TotpSetupResult:
    """Génère un secret TOTP en attente de confirmation (pas encore actif)."""
    document = await _get_user_or_401(user_id)
    secret = generate_secret()
    await db.users.update_one(
        {"_id": ObjectId(user_id)}, {"$set": {"totp_secret_pending": secret}}
    )
    return TotpSetupResult(secret=secret, uri=totp_uri(secret, document["email"]))


@router.post("/2fa/confirm", dependencies=[Depends(require_csrf)])
async def confirm_totp(
    payload: TotpCodeInput, user_id: str = Depends(get_current_user_id)
) -> dict[str, bool]:
    """Active la 2FA après vérification d'un premier code valide."""
    document = await _get_user_or_401(user_id)
    pending_secret = document.get("totp_secret_pending")
    if not pending_secret or not verify_code(pending_secret, payload.code):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Code invalide.")

    await db.users.update_one(
        {"_id": ObjectId(user_id)},
        {"$set": {"totp_secret": pending_secret}, "$unset": {"totp_secret_pending": ""}},
    )
    return {"enabled": True}


@router.post("/2fa/disable", dependencies=[Depends(require_csrf)])
async def disable_totp(
    payload: TotpCodeInput, user_id: str = Depends(get_current_user_id)
) -> dict[str, bool]:
    """Désactive la 2FA (re-authentification par code requise)."""
    document = await _get_user_or_401(user_id)
    secret = document.get("totp_secret")
    if not secret or not verify_code(secret, payload.code):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Code invalide.")

    await db.users.update_one({"_id": ObjectId(user_id)}, {"$unset": {"totp_secret": ""}})
    return {"enabled": False}


@router.post("/forgot-password", status_code=status.HTTP_202_ACCEPTED)
async def forgot_password(payload: ForgotPasswordRequest) -> None:
    """Toujours 202 (n'indique jamais si l'email correspond à un compte existant)."""
    document = await db.users.find_one({"email": payload.email})
    if document is None:
        return

    token = secrets.token_urlsafe(32)
    await redis_client.set(
        f"{_PASSWORD_RESET_PREFIX}{token}",
        str(document["_id"]),
        ex=_PASSWORD_RESET_TTL_SECONDS,
    )
    await asyncio.to_thread(
        send_mail,
        document["email"],
        "Reinitialisation de mot de passe",
        f"Jeton de reinitialisation (valide 30 minutes) : {token}",
    )


@router.post("/reset-password")
async def reset_password(payload: ResetPasswordRequest) -> dict[str, bool]:
    """Change le mot de passe à partir du jeton reçu par email."""
    key = f"{_PASSWORD_RESET_PREFIX}{payload.token}"
    user_id = await redis_client.get(key)
    if user_id is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Jeton invalide ou expiré."
        )

    error = validate_password_strength(payload.new_password)
    if error:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=error)

    await redis_client.delete(key)
    await db.users.update_one(
        {"_id": ObjectId(user_id)},
        {"$set": {"password_hash": hash_password(payload.new_password)}},
    )
    return {"reset": True}


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
    document = await _get_user_or_401(user_id)
    return UserPublic.from_document(document)
