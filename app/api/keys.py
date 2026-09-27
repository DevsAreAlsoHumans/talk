"""Echange de cles : uniquement des cles publiques et des cles deja chiffrees.

Le serveur peut distribuer une cle de canal, jamais la dechiffrer : chaque
destinataire recoit la cle chiffree avec sa propre cle publique.
"""

from fastapi import APIRouter, Depends, HTTPException, status
from redis import Redis

from app.api.deps import channel_access, current_user, require_csrf, salon_role
from app.db import get_redis
from app.repositories import keys, salons, users
from app.schemas_chat import (
    ChannelKeyIn,
    ChannelKeyOut,
    ChannelKeysOut,
    PublicKeyIn,
    PublicKeyOut,
)

router = APIRouter(tags=["keys"])


@router.put("/keys", response_model=PublicKeyOut, dependencies=[Depends(require_csrf)])
def publish_public_key(
    payload: PublicKeyIn,
    redis: Redis = Depends(get_redis),
    user: dict = Depends(current_user),
) -> PublicKeyOut:
    """Rotation de la cle d'identite ; la cle privee reste sur le poste client."""
    stored = keys.put_public_key(redis, user["id"], payload.public_key)
    return PublicKeyOut(user_id=user["id"], username=user["username"], **stored)


@router.get("/keys/{user_id}", response_model=PublicKeyOut)
def read_public_key(
    user_id: str,
    redis: Redis = Depends(get_redis),
    user: dict = Depends(current_user),
) -> PublicKeyOut:
    """Cle publique d'un membre d'un salon partage, jamais d'un inconnu."""
    shared = any(
        salons.get_role(redis, salon_id, user_id) is not None
        and salons.get_role(redis, salon_id, user["id"]) is not None
        for salon_id in redis.smembers(f"user:salons:{user['id']}")
    )
    if not shared:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Utilisateur introuvable."
        )
    stored = keys.get_public_key(redis, user_id)
    profile = users.get_by_id(redis, user_id)
    if stored is None or profile is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Cle publique introuvable."
        )
    return PublicKeyOut(
        user_id=user_id, username=profile["username"], public_key=stored["public_key"],
        version=stored["version"],
    )


@router.put(
    "/channels/{channel_id}/key",
    response_model=ChannelKeyOut,
    dependencies=[Depends(require_csrf)],
)
def publish_channel_key(
    channel_id: str,
    payload: ChannelKeyIn,
    channel: dict = Depends(channel_access),
    redis: Redis = Depends(get_redis),
    user: dict = Depends(current_user),
) -> ChannelKeyOut:
    """Depose la cle de canal chiffree pour soi-meme (rotation incluse)."""
    return ChannelKeyOut(**keys.put_channel_key(redis, channel_id, user["id"], payload.wrapped_key))


@router.get("/channels/{channel_id}/key", response_model=ChannelKeyOut)
def read_own_channel_key(
    channel_id: str,
    _channel: dict = Depends(channel_access),
    redis: Redis = Depends(get_redis),
    user: dict = Depends(current_user),
) -> ChannelKeyOut:
    stored = keys.get_channel_key(redis, channel_id, user["id"])
    if stored is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Cle de canal absente."
        )
    return ChannelKeyOut(**stored)


@router.get("/channels/{channel_id}/keys", response_model=ChannelKeysOut)
def read_channel_keys(
    channel_id: str,
    channel: dict = Depends(channel_access),
    redis: Redis = Depends(get_redis),
    _role: str = Depends(salon_role),
) -> ChannelKeysOut:
    """Toutes les cles de canal distribuees : sert a added un membre ouune rotation."""
    return ChannelKeysOut(
        keys={
            user_id: ChannelKeyOut(**entry)
            for user_id, entry in keys.list_channel_keys(redis, channel).items()
        }
    )
