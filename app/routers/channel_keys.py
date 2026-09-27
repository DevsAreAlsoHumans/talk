"""Distribution des enveloppes de clé de salon.

C'est le seul mécanisme par lequel une clé de salon franchit le serveur, et il
est volontairement à sens unique : le créateur produit, dans son navigateur, une
enveloppe destinée à un autre membre. Le serveur la stocke et la restitue, sans
jamais pouvoir l'ouvrir.

Le serveur ne peut pas initier cette distribution. Il ne détient pas la clé de
salon : personne ne la lui transmet en clair, et il ne dispose d'aucun moyen de
la reconstituer à partir des enveloppes des autres membres, dont il ne possède
pas les clés privées.

Un dépôt répété est accepté comme succès : après une reconnexion, le client ne
peut pas savoir si sa première tentative est parvenue.

Le dépôt est en revanche réservé au **créateur du serveur** parent. Le dépôt
étant « premier arrivé, premier servi » et jamais écrasé, un membre ordinaire
pourrait sinon déposer avant le créateur une enveloppe contenant une clé de salon
de son choix : le destinataire la déchiffrerait sans erreur, mais ne pourrait plus
lier aucun message chiffré avec la vraie clé, et lirait en revanche tout ce que
l'attaquant chiffrerait avec celle qu'il a imposée. Réserver le dépôt au
créateur rend cette préemption impossible ; la lecture de sa propre enveloppe,
elle, reste ouverte à tout membre du serveur.
"""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, status

from app.chat_schemas import ChannelKeyIn, ChannelKeyOut
from app.chat_store import ChatStore, to_object_id
from app.deps import (
    get_chat_store,
    get_current_user,
    require_channel_server,
    require_channel_server_creator,
    require_csrf,
)

router = APIRouter(tags=["clés de salon"])


@router.post(
    "/channels/{channel_id}/keys",
    response_model=ChannelKeyOut,
    status_code=status.HTTP_201_CREATED,
)
async def deposit_channel_key(
    channel_id: str,
    payload: ChannelKeyIn,
    _session: Annotated[dict[str, Any], Depends(require_csrf)],
    pair: Annotated[tuple[dict[str, Any], dict[str, Any]], Depends(require_channel_server_creator)],
    chat: Annotated[ChatStore, Depends(get_chat_store)],
) -> ChannelKeyOut:
    """Dépose une enveloppe de clé de salon pour un membre du serveur parent.

    Réservé au créateur du serveur : c'est la condition qui empêche un membre
    ordinaire de devancer la distribution et d'imposer sa propre clé de salon au
    destinataire. Un canal n'ayant plus de propriétaire, cette autorité est celle
    du serveur — c'est la seule règle qui rende le dépôt non préemptible.

    `wrapped_key` est le résultat de `RSA-OAEP(cle_publique_du_destinataire,
    cle_de_salon)`, calculé dans le navigateur du créateur. Le serveur vérifie
    uniquement que le destinataire appartient bien au serveur et que l'enveloppe a
    une taille plausible : il ne peut ni la déchiffrer, ni vérifier qu'elle
    correspond réellement à une clé de salon.
    """
    channel, server = pair
    target_id = to_object_id(payload.user_id)
    if target_id is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Utilisateur introuvable.")
    if not await chat.is_server_member(server["_id"], target_id):
        raise HTTPException(
            status.HTTP_409_CONFLICT, "Le destinataire n'est pas membre de ce serveur."
        )

    # `set_channel_key` renvoie False si une enveloppe existait déjà. La
    # réponse est alors identique : le dépôt est idempotent.
    await chat.set_channel_key(channel["_id"], target_id, payload.wrapped_key)
    stored = await chat.get_channel_key(channel["_id"], target_id)
    if stored is None:  # pragma: no cover - l'insertion vient d'être confirmée
        raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, "Dépôt impossible.")

    return ChannelKeyOut(
        channel_id=str(channel["_id"]),
        key_version=stored["key_version"],
        wrapped_key=stored["wrapped_key"],
        created_at=stored["created_at"],
    )


@router.get("/channels/{channel_id}/keys/me", response_model=ChannelKeyOut)
async def read_my_channel_key(
    channel_id: str,
    _pair: Annotated[tuple[dict[str, Any], dict[str, Any]], Depends(require_channel_server)],
    user: Annotated[dict[str, Any], Depends(get_current_user)],
    chat: Annotated[ChatStore, Depends(get_chat_store)],
) -> ChannelKeyOut:
    """Renvoie l'enveloppe de clé de salon destinée à l'appelant.

    La lecture, seule, reste ouverte à tout membre du serveur, et non au
    créateur : c'est le destinataire qui doit pouvoir récupérer la clé qu'on lui
    a transmise.

    Un membre sans enveloppe reçoit 404, ce qui n'est pas la même situation
    qu'un refus d'accès : le canal existe, il reste simplement à distribuer la
    clé. Le client.poll cette route jusqu'à ce que l'enveloppe apparaisse. Un
    tiers ne va pas jusqu'à ce 404, il est refusé par la dépendance.
    """
    channel, _server = _pair
    stored = await chat.get_channel_key(channel["_id"], user["_id"])
    if stored is None:
        raise HTTPException(
            status.HTTP_404_NOT_FOUND, "Aucune clé de salon ne vous a encore été distribuée."
        )
    return ChannelKeyOut(
        channel_id=str(stored["channel_id"]),
        key_version=stored["key_version"],
        wrapped_key=stored["wrapped_key"],
        created_at=stored["created_at"],
    )
