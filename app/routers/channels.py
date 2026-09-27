"""Création et consultation des canaux.

Un canal ne contient aucun secret : ni nom, ni liste de membres, ni clé de salon
n'est chiffré, et aucun n'est nécessaire pour le lire. La clé de salon n'existe
côté serveur que sous forme d'enveloppes destinées à chaque membre, déposées
séparément via le routeur `channel_keys`.

Un canal ne porte plus ni `members` ni `created_by` : il ne connaît que son
`server_id`. Toute autorisation passe par le serveur parent, et les routes de ce
fichier s'en remettent à `require_channel_server`, sans jamais recomposer une
liste de membres localement.
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
    require_channel_server,
    require_csrf,
    require_public_key,
    require_server_creator,
    require_server_member,
)

router = APIRouter(tags=["canaux"])


@router.get("/channels", response_model=list[ChannelOut])
async def list_channels(
    user: Annotated[dict[str, Any], Depends(get_current_user)],
    chat: Annotated[ChatStore, Depends(get_chat_store)],
) -> list[ChannelOut]:
    """Liste les canaux accessibles à l'appelant, tous serveurs confondus.

    Cette route est conservée pour le mécanisme de reprise du navigateur, qui
    s'appuie sur `client_ref` pour retrouver un canal créé juste avant une
    fermeture inattendue. Elle reste une route *plate*, et son autorisation n'a
    rien de spécial : `list_channels_for_user` relève d'abord les serveurs dont
    l'appelant est membre, puis ne retient que les canaux qui en dépendent. Un
    canal d'un serveur dont il n'est pas membre n'apparaît donc pas — le même
    critère que partout ailleurs, jamais une membership de canal.

    La navigation par serveur, elle, passe par `GET /servers/{id}/channels`.
    """
    channels = await chat.list_channels_for_user(user["_id"])
    return [channel_to_out(channel) for channel in channels]


@router.get("/servers/{server_id}/channels", response_model=list[ChannelOut])
async def list_server_channels(
    server: Annotated[dict[str, Any], Depends(require_server_member)],
    chat: Annotated[ChatStore, Depends(get_chat_store)],
) -> list[ChannelOut]:
    """Liste les canaux d'un serveur. Réservé à ses membres.

    C'est la route hiérarchique attendue : on entre par le serveur, on en tire
    ses canaux, et l'autorisation est celle du serveur — jamais celle d'un canal.
    Elle se justifie par rapport à `GET /channels`, qui reste plate : ici, un
    membre voit le contenu d'un serveur dont il fait partie, ce qui est
    précisément ce que la hiérarchie `User → Server → channels` doit permettre.
    """
    channels = await chat.list_channels_for_servers([server["_id"]])
    return [channel_to_out(channel) for channel in channels]


@router.post(
    "/servers/{server_id}/channels", response_model=ChannelOut, status_code=status.HTTP_201_CREATED
)
async def create_channel(
    server_id: str,
    payload: ChannelCreateIn,
    _session: Annotated[dict[str, Any], Depends(require_csrf)],
    _public_key: Annotated[dict[str, Any], Depends(require_public_key)],
    server: Annotated[dict[str, Any], Depends(require_server_creator)],
    chat: Annotated[ChatStore, Depends(get_chat_store)],
) -> ChannelOut:
    """Crée un canal dans le serveur dont l'appelant est le créateur.

    Le canal naît sans propriétaire et sans membres : il ne reçoit que son
    `server_id`. Son autorité et son public sont ceux du serveur.

    Aucune clé n'est reçue ici, et c'est délibéré : la clé de salon reste dans le
    navigateur du créateur, qui la déposera chiffrée pour lui-même juste après.
    Le canal peut donc exister quelques instants sans aucune enveloppe, ce que
    l'interface signale comme « non distribué » tant que la première n'est pas
    arrivée.
    """
    try:
        channel = await chat.create_channel(payload.name, server["_id"], str(payload.client_ref))
    except DuplicateKeyError as exc:
        raise HTTPException(
            status.HTTP_409_CONFLICT, "Un canal porte déjà cette référence locale."
        ) from exc
    return channel_to_out(channel)


@router.get("/channels/{channel_id}", response_model=ChannelOut)
async def read_channel(
    pair: Annotated[tuple[dict[str, Any], dict[str, Any]], Depends(require_channel_server)],
) -> ChannelOut:
    """Détaille un canal. Réservé aux membres de son serveur."""
    channel, _server = pair
    return channel_to_out(channel)
