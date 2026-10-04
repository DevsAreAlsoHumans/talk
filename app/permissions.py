"""Vérifications d'accès aux salons et aux canaux."""

from fastapi import HTTPException


# Vérifie que le salon existe et que je suis dedans
async def member(server_id: str, user_id: str, database) -> dict:
    server = await database.hgetall(f"server:{server_id}")
    if not server:
        raise HTTPException(404, "Salon introuvable")
    if not await database.sismember(f"server:{server_id}:members", user_id):
        raise HTTPException(403, "Accès refusé")
    return server


# Comme member(), mais seulement pour le créateur du salon
async def owner(server_id: str, user_id: str, database) -> dict:
    server = await member(server_id, user_id, database)
    if server["owner"] != user_id:
        raise HTTPException(403, "Réservé au créateur du salon")
    return server


# Vérifie que le canal appartient bien à ce salon
async def channel_in_server(server_id: str, channel_id: str, database) -> dict:
    channel = await database.hgetall(f"channel:{channel_id}")
    if not channel or channel.get("server_id") != server_id:
        raise HTTPException(404, "Canal introuvable")
    return channel


# Retrouve l'id d'un utilisateur à partir de son identifiant
async def user_id_of(username: str, database) -> str:
    user_id = await database.get(f"username:{username.lower()}")
    if not user_id:
        raise HTTPException(404, "Utilisateur introuvable")
    return user_id
