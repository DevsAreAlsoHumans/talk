"""Création et consultation des canaux.

Un canal ne contient aucun secret : ni nom, ni liste de membres, ni clé de salon
n'est chiffré, et aucun n'est nécessaire pour le lire. La clé de salon n'existe
côté serveur que sous forme d'enveloppes destinées à chaque membre, déposées
séparément via le routeur `channel_keys`.
"""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, status
from pymongo.errors import DuplicateKeyError

from app.chat_schemas import ChannelCreateIn, ChannelOut
from app.chat_store import ChatStore, channel_to_out
from app.deps import (
    get_chat_store,
    get_current_user,
    require_channel_member,
    require_csrf,
    require_public_key,
)

router = APIRouter(tags=["canaux"])


@router.get("/channels", response_model=list[ChannelOut])
async def list_channels(
    user: Annotated[dict[str, Any], Depends(get_current_user)],
    chat: Annotated[ChatStore, Depends(get_chat_store)],
) -> list[ChannelOut]:
    """Liste les canaux dont l'appelant est membre.

    `client_ref` est renvoyé au client qui a créé le canal : c'est lui qui
    permet de retrouver, après une fermeture du navigateur, le canal dont
    l'enveloppe n'a pas encore été déposée.
    """
    channels = await chat.list_channels_for_user(user["_id"])
    return [await channel_to_out(chat, channel) for channel in channels]


@router.post("/channels", response_model=ChannelOut, status_code=status.HTTP_201_CREATED)
async def create_channel(
    payload: ChannelCreateIn,
    _session: Annotated[dict[str, Any], Depends(require_csrf)],
    _public_key: Annotated[dict[str, Any], Depends(require_public_key)],
    user: Annotated[dict[str, Any], Depends(get_current_user)],
    chat: Annotated[ChatStore, Depends(get_chat_store)],
) -> ChannelOut:
    """Crée un canal dont l'appelant est le premier membre.

    Aucune clé n'est reçue ici, et c'est délibéré : la clé de salon reste dans
    le navigateur du créateur, qui la déposera chiffrée pour lui-même juste
    après. Le canal peut donc exister quelques instants sans aucune enveloppe,
    ce que l'interface signale comme « non distribué » tant que la première
    n'est pas arrivée.
    """
    try:
        channel = await chat.create_channel(payload.name, user["_id"], str(payload.client_ref))
    except DuplicateKeyError as exc:
        raise HTTPException(
            status.HTTP_409_CONFLICT, "Un canal porte déjà cette référence locale."
        ) from exc
    return await channel_to_out(chat, channel)


@router.get("/channels/{channel_id}", response_model=ChannelOut)
async def read_channel(
    channel: Annotated[dict[str, Any], Depends(require_channel_member)],
    chat: Annotated[ChatStore, Depends(get_chat_store)],
) -> ChannelOut:
    """Détaille un canal. Réservé aux membres."""
    return await channel_to_out(chat, channel)
