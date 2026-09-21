"""Authentification : register, login, logout, profile courant.

CSRF appliqué sur toutes les mutations (middleware). Rate-limit de
login/register : 429 au-delà de ``MAX_LOGIN_ATTEMPTS`` échecs.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from redis import Redis

from app.api.deps import client_ip, get_current_user
from app.db.redis import get_redis
from app.repositories import rooms as rooms_repo
from app.repositories import users
from app.schemas import AuthResponse, ChangePasswordRequest, LoginRequest, RegisterRequest
from app.security import passwords
from app.security.passwords import hash_password, verify_password
from app.security.ratelimit import login_rate_limited, reset_login_rate_limit
from app.security.sessions import (
    clear_session_cookie,
    create_session,
    destroy_session,
    read_session_id,
    rotate_session,
    set_session_cookie,
)

router = APIRouter(prefix="/auth", tags=["auth"])

# Routes de l'utilisateur courant, exposées à la racine : ``GET /api/me``.
me_router = APIRouter(tags=["auth"])


def _rotate_to_user(redis: Redis, request: Request, user_id: str) -> tuple[str, str]:
    """Rotation de la session (anonyme ou existante) vers un utilisateur.

    Anti-fixation de session : nouveau sid + nouveau token CSRF, l'ancienne
    session étant invalidée à la création.
    """
    sid = read_session_id(request)
    if sid is None:
        sid, _ = create_session(redis, user_id=None)
    return rotate_session(redis, sid, user_id=user_id)


@router.post("/register", response_model=AuthResponse, status_code=201)
def register(
    body: RegisterRequest,
    request: Request,
    response: Response,
    redis: Redis = Depends(get_redis),
) -> dict:
    """Inscription : crée l'utilisateur puis effectue une rotation de session."""
    ip = client_ip(request)
    if login_rate_limited(redis, ip, body.username):
        raise HTTPException(status_code=429, detail="Too many attempts, please retry later")

    password_hash = hash_password(body.password)
    user = users.create_user(redis, body.username, password_hash, body.public_key)
    if user is None:
        raise HTTPException(status_code=409, detail="Username already taken")

    new_sid, new_token = _rotate_to_user(redis, request, user["id"])
    set_session_cookie(response, new_sid)
    return {"user": users.to_public(user), "csrf_token": new_token}


@router.post("/login", response_model=AuthResponse)
def login(
    body: LoginRequest,
    request: Request,
    response: Response,
    redis: Redis = Depends(get_redis),
) -> dict:
    """Connexion : vérifie le mot de passe puis effectue une rotation de session."""
    ip = client_ip(request)
    if login_rate_limited(redis, ip, body.username):
        raise HTTPException(status_code=429, detail="Too many attempts, please retry later")

    user = users.get_by_username(redis, body.username)
    if user is None or not verify_password(body.password, user["password_hash"]):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    reset_login_rate_limit(redis, ip, body.username)
    new_sid, new_token = _rotate_to_user(redis, request, user["id"])
    set_session_cookie(response, new_sid)
    return {"user": users.to_public(user), "csrf_token": new_token}


@router.post("/change-password", status_code=204)
def change_password(
    body: ChangePasswordRequest,
    response: Response,
    user: dict = Depends(get_current_user),
    redis: Redis = Depends(get_redis),
) -> Response:
    """Change le mot de passe de l'utilisateur courant (ancien mot de passe vérifié).

    Décision assumée : le changement n'invalide PAS les sessions existantes
    (la rotation de session reste réservée à login/register).
    """
    stored = users.get_by_id(redis, user["id"])
    if stored is None or not passwords.verify_password(body.old_password, stored["password_hash"]):
        raise HTTPException(status_code=403, detail="Incorrect current password")

    users.update_password(redis, user["id"], passwords.hash_password(body.new_password))
    response.status_code = 204
    return response


@router.post("/logout", status_code=204)
def logout(
    request: Request,
    response: Response,
    redis: Redis = Depends(get_redis),
) -> Response:
    """Déconnexion : détruit la session et efface le cookie.

    On retourne la réponse injectée (et non un nouvel objet ``Response``),
    sans quoi le header ``Set-Cookie`` de suppression serait perdu.
    """
    destroy_session(redis, request)
    response.status_code = 204
    clear_session_cookie(response)
    return response


@me_router.get("/me")
def me(
    user: dict = Depends(get_current_user),
    redis: Redis = Depends(get_redis),
) -> dict:
    """Profil courant (utilisateur public + liste de ses salons ``{id, name}``)."""
    rooms = rooms_repo.list_for_user(redis, user["id"])
    return {
        "user": users.to_public(user),
        "rooms": [{"id": room["id"], "name": room["name"]} for room in rooms],
    }
