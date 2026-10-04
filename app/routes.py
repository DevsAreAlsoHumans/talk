"""Routes de l'API : comptes, salons, canaux et messages."""

import json
import secrets
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Request, Response

from app.database import db
from app.models import Credentials, EncryptedMessage, Named
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

router = APIRouter(prefix="/api")

# Nombre de messages renvoyés pour un canal
HISTORY_SIZE = 100


# Vérifie que le salon existe et que je suis dedans
async def member(server_id: str, user_id: str, database) -> dict:
    server = await database.hgetall(f"server:{server_id}")
    if not server:
        raise HTTPException(404, "Salon introuvable")
    if not await database.sismember(f"server:{server_id}:members", user_id):
        raise HTTPException(403, "Accès refusé")
    return server


# Vérifie que le canal appartient bien à ce salon
async def channel_in_server(server_id: str, channel_id: str, database) -> dict:
    channel = await database.hgetall(f"channel:{channel_id}")
    if not channel or channel.get("server_id") != server_id:
        raise HTTPException(404, "Canal introuvable")
    return channel


# ---------- Comptes ----------

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


# Qui est connecté ?
@router.get("/me")
async def me(user_id: str = Depends(current_user), database=Depends(db)):
    return {"username": await database.hget(f"user:{user_id}", "username")}


# ---------- Salons ----------

# Liste de mes salons
@router.get("/servers")
async def list_servers(user_id: str = Depends(current_user), database=Depends(db)):
    servers = []
    for server_id in await database.smembers(f"user:{user_id}:servers"):
        name = await database.hget(f"server:{server_id}", "name")
        if name:
            servers.append({"id": server_id, "name": name})
    return sorted(servers, key=lambda server: server["name"].lower())


# Création d'un salon avec un canal « général » par défaut
@router.post("/servers", dependencies=[Depends(csrf)])
async def create_server(data: Named, user_id: str = Depends(current_user), database=Depends(db)):
    server_id = secrets.token_urlsafe(12)
    channel_id = secrets.token_urlsafe(12)
    # Pipeline : tout est envoyé à Redis d'un coup
    pipe = database.pipeline()
    pipe.hset(f"server:{server_id}", mapping={"name": data.name, "owner": user_id})
    pipe.sadd(f"server:{server_id}:members", user_id)
    pipe.sadd(f"user:{user_id}:servers", server_id)
    pipe.hset(f"channel:{channel_id}", mapping={"name": "général", "server_id": server_id})
    pipe.rpush(f"server:{server_id}:channels", channel_id)
    await pipe.execute()
    return {"id": server_id, "name": data.name, "channel_id": channel_id}


# Rejoindre un salon via le lien d'invitation
@router.post("/servers/{server_id}/join", dependencies=[Depends(csrf)])
async def join_server(server_id: str, user_id: str = Depends(current_user), database=Depends(db)):
    name = await database.hget(f"server:{server_id}", "name")
    if not name:
        raise HTTPException(404, "Salon introuvable")
    pipe = database.pipeline()
    pipe.sadd(f"server:{server_id}:members", user_id)
    pipe.sadd(f"user:{user_id}:servers", server_id)
    await pipe.execute()
    return {"id": server_id, "name": name}


# ---------- Canaux ----------

# Liste des canaux (membres seulement)
@router.get("/servers/{server_id}/channels")
async def list_channels(server_id: str, user_id: str = Depends(current_user), database=Depends(db)):
    await member(server_id, user_id, database)
    channels = []
    for channel_id in await database.lrange(f"server:{server_id}:channels", 0, -1):
        name = await database.hget(f"channel:{channel_id}", "name")
        if name:
            channels.append({"id": channel_id, "name": name})
    return channels


# Ajout d'un canal (seulement le créateur du salon)
@router.post("/servers/{server_id}/channels", dependencies=[Depends(csrf)])
async def create_channel(
    server_id: str, data: Named, user_id: str = Depends(current_user), database=Depends(db)
):
    server = await member(server_id, user_id, database)
    if server["owner"] != user_id:
        raise HTTPException(403, "Seul le créateur peut ajouter un canal")
    channel_id = secrets.token_urlsafe(12)
    pipe = database.pipeline()
    pipe.hset(f"channel:{channel_id}", mapping={"name": data.name, "server_id": server_id})
    pipe.rpush(f"server:{server_id}:channels", channel_id)
    await pipe.execute()
    return {"id": channel_id, "name": data.name}


# ---------- Messages ----------

# Les derniers messages chiffrés du canal
@router.get("/servers/{server_id}/channels/{channel_id}/messages")
async def list_messages(
    server_id: str, channel_id: str, user_id: str = Depends(current_user), database=Depends(db)
):
    await member(server_id, user_id, database)
    await channel_in_server(server_id, channel_id, database)
    rows = await database.lrange(f"channel:{channel_id}:messages", -HISTORY_SIZE, -1)
    return [json.loads(row) for row in rows]


# Envoi d'un message chiffré, le serveur le stocke tel quel
@router.post("/servers/{server_id}/channels/{channel_id}/messages", dependencies=[Depends(csrf)])
async def send_message(
    server_id: str, channel_id: str, data: EncryptedMessage,
    user_id: str = Depends(current_user), database=Depends(db),
):
    await member(server_id, user_id, database)
    await channel_in_server(server_id, channel_id, database)
    message = {
        "id": secrets.token_urlsafe(12),
        "author": await database.hget(f"user:{user_id}", "username"),
        "created_at": datetime.now(timezone.utc).isoformat(),
        "version": data.version, "nonce": data.nonce, "ciphertext": data.ciphertext,
    }
    await database.rpush(f"channel:{channel_id}:messages", json.dumps(message))
    return message
