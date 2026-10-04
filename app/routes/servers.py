"""Salons : création, membres, clés chiffrées et canaux."""

import secrets

from fastapi import APIRouter, Depends, HTTPException, Path

from app.database import db
from app.models import USERNAME, Named, NewMember, NewServer
from app.permissions import member, owner, user_id_of
from app.security import csrf, current_user

router = APIRouter()


# Liste de mes salons
@router.get("/servers")
async def list_servers(user_id: str = Depends(current_user), database=Depends(db)):
    servers = []
    for server_id in await database.smembers(f"user:{user_id}:servers"):
        server = await database.hgetall(f"server:{server_id}")
        if server:
            servers.append({"id": server_id, "name": server["name"], "owner": server["owner"] == user_id})
    return sorted(servers, key=lambda server: server["name"].lower())


# Création d'un salon avec un canal « général » par défaut
@router.post("/servers", dependencies=[Depends(csrf)])
async def create_server(data: NewServer, user_id: str = Depends(current_user), database=Depends(db)):
    server_id = secrets.token_urlsafe(12)
    channel_id = secrets.token_urlsafe(12)
    # Pipeline : tout est envoyé à Redis d'un coup
    pipe = database.pipeline()
    pipe.hset(f"server:{server_id}", mapping={"name": data.name, "owner": user_id})
    pipe.sadd(f"server:{server_id}:members", user_id)
    pipe.sadd(f"user:{user_id}:servers", server_id)
    # La clé du salon, chiffrée avec ma clé publique : le serveur ne peut pas la lire
    pipe.hset(f"server:{server_id}:keys", user_id, data.wrapped_key)
    pipe.hset(f"channel:{channel_id}", mapping={"name": "général", "server_id": server_id})
    pipe.rpush(f"server:{server_id}:channels", channel_id)
    await pipe.execute()
    return {"id": server_id, "name": data.name, "owner": True, "channel_id": channel_id}


# Ma copie chiffrée de la clé du salon (le navigateur la déchiffre avec ma clé privée)
@router.get("/servers/{server_id}/key")
async def my_server_key(server_id: str, user_id: str = Depends(current_user), database=Depends(db)):
    await member(server_id, user_id, database)
    wrapped_key = await database.hget(f"server:{server_id}:keys", user_id)
    if not wrapped_key:
        raise HTTPException(404, "Pas de clé pour vous, demandez au créateur de vous ajouter à nouveau")
    return {"wrapped_key": wrapped_key}


# ---------- Membres ----------

# Liste des membres du salon
@router.get("/servers/{server_id}/members")
async def list_members(server_id: str, user_id: str = Depends(current_user), database=Depends(db)):
    server = await member(server_id, user_id, database)
    members = []
    for member_id in await database.smembers(f"server:{server_id}:members"):
        username = await database.hget(f"user:{member_id}", "username")
        members.append({"username": username, "owner": member_id == server["owner"]})
    return sorted(members, key=lambda item: (not item["owner"], item["username"]))


# Ajout d'un membre (créateur seulement). Le navigateur a chiffré la clé du salon pour lui.
# Si le membre existe déjà, sa clé est remplacée (utile s'il a changé d'appareil)
@router.post("/servers/{server_id}/members", dependencies=[Depends(csrf)])
async def add_member(
    server_id: str, data: NewMember, user_id: str = Depends(current_user), database=Depends(db)
):
    await owner(server_id, user_id, database)
    new_member_id = await user_id_of(data.username, database)
    pipe = database.pipeline()
    pipe.sadd(f"server:{server_id}:members", new_member_id)
    pipe.sadd(f"user:{new_member_id}:servers", server_id)
    pipe.hset(f"server:{server_id}:keys", new_member_id, data.wrapped_key)
    await pipe.execute()
    return {"username": data.username.lower(), "owner": False}


# Retrait d'un membre (créateur seulement) : il perd l'accès et sa copie de la clé
@router.delete("/servers/{server_id}/members/{username}", dependencies=[Depends(csrf)])
async def remove_member(
    server_id: str, username: str = Path(pattern=USERNAME),
    user_id: str = Depends(current_user), database=Depends(db),
):
    server = await owner(server_id, user_id, database)
    removed_id = await user_id_of(username, database)
    if removed_id == server["owner"]:
        raise HTTPException(400, "Le créateur ne peut pas être retiré")
    if not await database.sismember(f"server:{server_id}:members", removed_id):
        raise HTTPException(404, "Cet utilisateur n'est pas dans le salon")
    pipe = database.pipeline()
    pipe.srem(f"server:{server_id}:members", removed_id)
    pipe.srem(f"user:{removed_id}:servers", server_id)
    pipe.hdel(f"server:{server_id}:keys", removed_id)
    await pipe.execute()
    return {"ok": True}


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
    await owner(server_id, user_id, database)
    channel_id = secrets.token_urlsafe(12)
    pipe = database.pipeline()
    pipe.hset(f"channel:{channel_id}", mapping={"name": data.name, "server_id": server_id})
    pipe.rpush(f"server:{server_id}:channels", channel_id)
    await pipe.execute()
    return {"id": channel_id, "name": data.name}
