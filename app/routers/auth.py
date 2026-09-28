"""Routeur d'authentification : inscription / connexion / session.

Flux CSRF double-submit :
   1. Le client appelle GET /api/auth/csrf -> le serveur pose le cookie `talk_csrf`
   2. Toute requête de mutation envoie ce cookie PLUS le header X-CSRF-Token
   3. Le serveur compare les deux à temps constant -> 403 si écart.
"""

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Response, status

from ..db import Database, get_db
from ..deps import (
    CSRF_COOKIE,
    SESSION_COOKIE,
    get_csrf_cookie_params,
    get_current_user,
    require_csrf,
)
from ..models import UserLogin, UserPublic, UserRegister, _UserOut
from ..ratelimit import rate_limit
from ..security import (
    create_session_token,
    hash_password,
    new_csrf_token,
    verify_password,
)

router = APIRouter(prefix="/api/auth", tags=["auth"])

DbDep = Annotated[Database, Depends(get_db)]
CurrentUser = Annotated[UserPublic, Depends(get_current_user)]


@router.post("/register", status_code=status.HTTP_201_CREATED, response_model=UserPublic)
async def register(
    payload: UserRegister,
    response: Response,
    db: DbDep,
    _: None = Depends(require_csrf),  # ligne de défense anti-abus d'inscription
    __: None = Depends(rate_limit()),  # anti force-brute / spam de comptes
):
    user = await db.get_user_by_username(payload.username)
    if user is not None:
        # Réponse volontairement vague : évite l'oracle d'énumération de comptes.
        raise HTTPException(status_code=409, detail="Ce pseudo est déjà pris")

    # Argon2id avant insertion : si l'insertion échoue, jamais de hash calculé en vain.
    password_hash = hash_password(payload.password)
    created = await db.create_user(payload.username, password_hash)
    if created is None:  # course : un autre enregistrement a gagné entre-temps
        raise HTTPException(status_code=409, detail="Ce pseudo est déjà pris")

    _set_session(response, created)
    return _UserOut.of(created)


@router.post("/login", response_model=UserPublic)
async def login(
    payload: UserLogin,
    response: Response,
    db: DbDep,
    _: None = Depends(require_csrf),
    __: None = Depends(rate_limit()),
):
    user = await db.get_user_by_username(payload.username)
    # Vérifie même quand l'utilisateur n'existe pas : coût d'argon2 constant
    # -> pas d'oracle temporel sur l'existence du compte.
    if user is None or not verify_password(payload.password, user["password_hash"]):
        raise HTTPException(status_code=401, detail="Identifiants invalides")

    _set_session(response, user)
    return _UserOut.of(user)


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
async def logout(
    response: Response,
    user: CurrentUser,
    _: None = Depends(require_csrf),  # mutation : CSRF obligatoire
):
    # Expire immédiatement les cookies : aucune session résiduelle côté client.
    response.delete_cookie(SESSION_COOKIE, **get_csrf_cookie_params(http_only=True))
    response.delete_cookie(CSRF_COOKIE, **get_csrf_cookie_params())
    response.status_code = status.HTTP_204_NO_CONTENT
    return response


@router.get("/me", response_model=UserPublic)
async def me(user: CurrentUser):
    return user


@router.get("/csrf")
async def csrf_token(response: Response) -> dict[str, str]:
    """Pose le cookie CSRF (lisible en JS pour le double-submit) et le renvoie."""
    token = new_csrf_token()
    response.set_cookie(key=CSRF_COOKIE, value=token, **get_csrf_cookie_params())
    return {"csrf_token": token}


def _set_session(response: Response, user: dict) -> None:
    """Pose la session signée (HttpOnly !) + un nouveau jeton CSRF (rotation).

    HttpOnly : le JS et le XSS ne peuvent pas lire le cookie de session.
    Rotation CSRF à chaque login = tout jeton pré-volé devient inutilisable.
    """
    token = create_session_token({"uid": str(user["_id"])})
    response.set_cookie(key=SESSION_COOKIE, value=token, **get_csrf_cookie_params(http_only=True))
    response.set_cookie(key=CSRF_COOKIE, value=new_csrf_token(), **get_csrf_cookie_params())
