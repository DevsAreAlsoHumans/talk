"""Gestion des membres d'un canal.

L'appartenance est une notion **serveur** : elle décide de qui peut lire un
historique et déposer un message. Elle ne dit rien de la cryptographie. Un
membre retiré conserve la clé de salon qu'il possède et peut donc continuer à
déchiffrer ce qui lui parvient ; seule une rotation de clé permettrait de le
déposséder, et il n'y en a pas dans le MVP.

Adhérer, retirer et distribuer la clé de salon sont en revanche des actes
réservés au **créateur** du canal, seule autorité de sa composition. Un membre
ordinaire pourrait, lui, inviter des inconnus ou évincer quelqu'un, et surtout
déposer une enveloppe à la place du créateur : le dépôt étant « premier arrivé,
premier servi », cela lui permettrait de fixer une clé de salon de son choix chez un
autre membre. Le créateur ne peut pas non plus se retirer lui-même : un canal
sans créateur n'aurait plus personne pour l'administrer ni pour distribuer sa
clé.
"""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, status

from app.chat_schemas import ChannelOut, MemberRefIn
from app.chat_store import ChatStore, channel_to_out, to_object_id
from app.deps import (
    get_chat_store,
    get_current_user,
    get_store,
    require_channel_creator,
    require_csrf,
)
from app.store import UserStore

router = APIRouter(tags=["membres"])


@router.post("/channels/{channel_id}/members", response_model=ChannelOut)
async def add_member(
    payload: MemberRefIn,
    _session: Annotated[dict[str, Any], Depends(require_csrf)],
    channel: Annotated[dict[str, Any], Depends(require_channel_creator)],
    user: Annotated[dict[str, Any], Depends(get_current_user)],
    chat: Annotated[ChatStore, Depends(get_chat_store)],
    store: Annotated[UserStore, Depends(get_store)],
) -> ChannelOut:
    """Ajoute un membre au canal. Réservé au créateur.

    Ajouter un membre ne lui donne pas accès au contenu : il lui faudra ensuite
    une enveloppe de clé de salon, que le créateur produit dans son navigateur.
    Le serveur ne peut pas le faire à sa place.
    """
    target_id = to_object_id(payload.user_id)
    if target_id is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Utilisateur introuvable.")
    if target_id == user["_id"]:
        raise HTTPException(status.HTTP_409_CONFLICT, "Vous êtes déjà membre de ce canal.")
    if await store.get_user_by_id(target_id) is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Utilisateur introuvable.")

    await chat.add_member(channel["_id"], target_id)
    refreshed = await chat.get_channel(channel["_id"])
    return await channel_to_out(chat, refreshed or channel)


@router.delete("/channels/{channel_id}/members/{user_id}", response_model=ChannelOut)
async def remove_member(
    channel_id: str,
    user_id: str,
    _session: Annotated[dict[str, Any], Depends(require_csrf)],
    channel: Annotated[dict[str, Any], Depends(require_channel_creator)],
    user: Annotated[dict[str, Any], Depends(get_current_user)],
    chat: Annotated[ChatStore, Depends(get_chat_store)],
) -> ChannelOut:
    """Retire un membre du canal. Réservé au créateur.

    Effet strictement serveur : le membre perd l'accès aux routes et au temps
    réel, mais garde la clé de salon qu'il possède. Sans rotation, il peut
    encore déchiffrer tout message qui lui serait transmis.

    Le créateur ne peut pas se retirer lui-même. C'est refusé même si d'autres
    membres subsistent, et pas seulement quand il est le dernier : ce n'est pas
    le nombre de membres qui rendrait l'état incohérent, c'est l'absence de
    créateur.
    """
    target_id = to_object_id(user_id)
    if target_id is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Utilisateur introuvable.")

    if target_id == user["_id"]:
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            "Le créateur ne peut pas quitter son propre canal : il est le seul à "
            "pouvoir ajouter des membres et distribuer la clé de salon.",
        )

    await chat.remove_member(channel["_id"], target_id)
    # L'enveloppe du membre retiré est supprimée avec son accès : il ne doit
    # plus pouvoir la récupérer par l'API. Cela ne retire rien à ce qu'il
    # possède déjà localement.
    await chat.drop_channel_key(channel["_id"], target_id)
    refreshed = await chat.get_channel(channel["_id"])
    return await channel_to_out(chat, refreshed or channel)
