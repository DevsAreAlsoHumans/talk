"""Routes d'authentification : bootstrap CSRF, inscription, connexion, déconnexion.

`GET /auth/csrf` amorce le mécanisme : il crée une session *anonyme* et pose les
deux cookies, ce qui permet de protéger ensuite `register` et `login`, qui sont
des mutations alors qu'aucune session authentifiée n'existe encore.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Request, Response, WebSocket, status

from app.config import CSRF_COOKIE_NAME, SESSION_COOKIE_NAME, get_settings
from app.deps import (
    enforce_login_rate_limit,
    get_current_user,
    get_current_user_ws,
    get_store,
    require_csrf,
    require_trusted_origin_ws,
    reset_login_rate_limit,
)
from app.schemas import CsrfOut, LoginIn, RegisterIn, UserPublic, normalize_username
from app.security import burn_password_verification, hash_password, verify_password
from app.store import DuplicateUsernameError, NewSession, UserStore

router = APIRouter(tags=["authentification"])

# Message unique pour un identifiant inconnu et un mot de passe erroné : il ne
# doit rien révéler sur l'existence d'un compte.
INVALID_CREDENTIALS = "Identifiants invalides."


def set_session_cookies(response: Response, session: NewSession) -> None:
    """Pose `talk_session` (HttpOnly) et `talk_csrf` (lisible par le JS)."""
    settings = get_settings()
    max_age = max(0, int((session.expires_at - datetime.now(UTC)).total_seconds()))
    response.set_cookie(
        SESSION_COOKIE_NAME,
        session.token,
        max_age=max_age,
        path="/",
        httponly=True,
        samesite="lax",
        secure=settings.cookie_secure,
    )
    response.set_cookie(
        CSRF_COOKIE_NAME,
        session.csrf_token,
        max_age=max_age,
        path="/",
        httponly=False,
        samesite="lax",
        secure=settings.cookie_secure,
    )


def clear_session_cookies(response: Response) -> None:
    """Supprime les deux cookies. Les attributs doivent correspondre à ceux posés."""
    settings = get_settings()
    for name, httponly in ((SESSION_COOKIE_NAME, True), (CSRF_COOKIE_NAME, False)):
        response.delete_cookie(
            name,
            path="/",
            httponly=httponly,
            samesite="lax",
            secure=settings.cookie_secure,
        )


@router.get("/auth/csrf", response_model=CsrfOut)
async def issue_csrf(
    request: Request,
    response: Response,
    store: Annotated[UserStore, Depends(get_store)],
) -> CsrfOut:
    """Bootstrap CSRF : garantit un couple (session, jeton CSRF) utilisable.

    Idempotent : si une session valide existe déjà, son jeton est renvoyé tel
    quel. Un second onglet ne casse donc pas le premier, et un appel répété ne
    crée pas de documents superflus.
    """
    token = request.cookies.get(SESSION_COOKIE_NAME)
    session = await store.get_session(token) if token else None
    if session is not None and session.get("csrf_token"):
        current = NewSession(
            token=str(token),
            csrf_token=str(session["csrf_token"]),
            expires_at=session["expires_at"],
        )
    else:
        current = await store.create_anonymous_session()
    set_session_cookies(response, current)
    # Cette réponse a un effet de bord : elle ne doit jamais être mise en cache.
    response.headers["Cache-Control"] = "no-store"
    return CsrfOut(csrf_token=current.csrf_token)


@router.post("/auth/register", response_model=UserPublic, status_code=status.HTTP_201_CREATED)
async def register(
    payload: RegisterIn,
    response: Response,
    session: Annotated[dict[str, Any], Depends(require_csrf)],
    store: Annotated[UserStore, Depends(get_store)],
) -> UserPublic:
    """Crée un compte puis ouvre une session authentifiée."""
    try:
        user = await store.create_user(payload.username, hash_password(payload.password))
    except DuplicateUsernameError as exc:
        raise HTTPException(
            status.HTTP_409_CONFLICT, "Ce nom d'utilisateur est déjà pris."
        ) from exc
    await store.delete_session_by_hash(str(session["token_hash"]))
    opened = await store.create_user_session(user["_id"])
    set_session_cookies(response, opened)
    return UserPublic.from_document(user)


@router.post("/auth/login", response_model=UserPublic)
async def login(
    payload: LoginIn,
    request: Request,
    response: Response,
    session: Annotated[dict[str, Any], Depends(require_csrf)],
    store: Annotated[UserStore, Depends(get_store)],
) -> UserPublic:
    """Vérifie les identifiants puis ouvre une session."""
    username = normalize_username(payload.username)
    enforce_login_rate_limit(request, username)
    user = await store.get_user_by_username(username)
    if user is None:
        # Sans ce hachage factife, le temps de réponse révélerait l'existence
        # du compte.
        burn_password_verification(payload.password)
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, INVALID_CREDENTIALS)
    if not verify_password(payload.password, str(user["password_hash"])):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, INVALID_CREDENTIALS)
    reset_login_rate_limit(request, username)
    # Rotation des deux jetons à l'authentification (protection contre la fixation
    # de session) : l'ancienne session anonyme est supprimée.
    await store.delete_session_by_hash(str(session["token_hash"]))
    opened = await store.create_user_session(user["_id"])
    set_session_cookies(response, opened)
    return UserPublic.from_document(user)


@router.post("/auth/logout", status_code=status.HTTP_204_NO_CONTENT)
async def logout(
    response: Response,
    session: Annotated[dict[str, Any], Depends(require_csrf)],
    store: Annotated[UserStore, Depends(get_store)],
) -> None:
    """Supprime la session côté serveur puis efface les cookies."""
    await store.delete_session_by_hash(str(session["token_hash"]))
    clear_session_cookies(response)


@router.get("/auth/me", response_model=UserPublic)
async def me(user: Annotated[dict[str, Any], Depends(get_current_user)]) -> UserPublic:
    """Retourne l'utilisateur de la session courante."""
    return UserPublic.from_document(user)


@router.websocket("/ws")
async def websocket_endpoint(
    websocket: WebSocket,
    _origin: Annotated[None, Depends(require_trusted_origin_ws)],
    user: Annotated[dict[str, Any], Depends(get_current_user_ws)],
) -> None:
    """Point d'entrée WebSocket : simple écho de l'identité, sans messagerie.

    L'origine est vérifiée avant toute lecture en base, et la session avant
    `accept()`. Un échec ferme la connexion en 1008 (violation de politique).
    """
    await websocket.accept()
    await websocket.send_json(
        {"status": "connecté", "user": UserPublic.from_document(user).model_dump(mode="json")}
    )
    await websocket.close()
