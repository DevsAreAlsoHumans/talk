"""Comptes : inscription, connexion, déconnexion et clés publiques."""

import secrets

from fastapi import APIRouter, Depends, HTTPException, Path, Request, Response

from app.database import db
from app.models import USERNAME, Credentials, PublicKey
from app.permissions import user_id_of
from app.security import (
    check_login_allowed,
    check_password,
    csrf,
    current_user,
    hash_password,
    login_failures_key,
    open_session,
    record_login_failure,
    set_cookie,
)

router = APIRouter()


# Donne un jeton CSRF au navigateur
@router.get("/csrf")
async def get_csrf(request: Request, response: Response):
    token = secrets.token_urlsafe(32)
    set_cookie(request, response, "csrf_token", token)
    return {"csrf_token": token}


# Inscription
@router.post("/signup", dependencies=[Depends(csrf)])
async def signup(data: Credentials, request: Request, response: Response, database=Depends(db)):
    username = data.username.lower()
    user_id = secrets.token_urlsafe(16)
    # nx=True : échoue si le pseudo existe déjà
    if not await database.set(f"username:{username}", user_id, nx=True):
        raise HTTPException(409, "Cet identifiant est déjà pris")
    await database.hset(
        f"user:{user_id}", mapping={"username": username, "password_hash": hash_password(data.password)}
    )
    await open_session(request, response, database, user_id)
    return {"username": username}


# Connexion
@router.post("/login", dependencies=[Depends(csrf)])
async def login(data: Credentials, request: Request, response: Response, database=Depends(db)):
    username = data.username.lower()
    failures_key = login_failures_key(request, username)
    await check_login_allowed(database, failures_key)
    user_id = await database.get(f"username:{username}")
    password_hash = await database.hget(f"user:{user_id}", "password_hash") if user_id else None
    # Même message si le compte n'existe pas ou si le mot de passe est faux
    if not check_password(data.password, password_hash):
        await record_login_failure(database, failures_key)
        raise HTTPException(401, "Identifiant ou mot de passe incorrect")
    await database.delete(failures_key)
    await open_session(request, response, database, user_id)
    return {"username": username}


# Déconnexion : on supprime la session dans Redis
@router.post("/logout", dependencies=[Depends(csrf)])
async def logout(request: Request, response: Response, database=Depends(db)):
    token = request.cookies.get("session")
    if token:
        await database.delete(f"session:{token}")
    response.delete_cookie("session")
    return {"ok": True}


# Qui est connecté ? (+ sa clé publique, pour que le navigateur vérifie qu'elle est à jour)
@router.get("/me")
async def me(user_id: str = Depends(current_user), database=Depends(db)):
    username, public_key = await database.hmget(f"user:{user_id}", ["username", "public_key"])
    return {"username": username, "public_key": public_key}


# Le navigateur envoie la clé publique de l'utilisateur (jamais la clé privée)
@router.put("/me/public-key", dependencies=[Depends(csrf)])
async def save_public_key(data: PublicKey, user_id: str = Depends(current_user), database=Depends(db)):
    await database.hset(f"user:{user_id}", "public_key", data.public_key)
    return {"ok": True}


# Clé publique d'un autre utilisateur, pour lui chiffrer la clé d'un salon
@router.get("/users/{username}/public-key")
async def get_public_key(
    username: str = Path(pattern=USERNAME), user_id: str = Depends(current_user), database=Depends(db)
):
    public_key = await database.hget(f"user:{await user_id_of(username, database)}", "public_key")
    if not public_key:
        raise HTTPException(404, "Cet utilisateur doit d'abord se connecter une fois")
    return {"username": username.lower(), "public_key": public_key}
