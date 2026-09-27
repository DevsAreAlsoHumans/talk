"""Routes des serveurs : création, consultation, adhésion et canaux.

L'appartenance est gérée ici et nulle part ailleurs. C'est la conséquence directe
du déplacement de la membership vers le serveur : il existe une seule liste de
membres, celle de `servers.members`, et elle décide de tout — lire un canal,
lire son historique, déposer un message, récupérer son enveloppe de clé.

Un canal ne se retire pas tout seul d'un serveur, et un serveur ne quitte pas un
canal : c'est le sens de la hiérarchie. Retirer quelqu'un d'un serveur le retire
de tous ses canaux d'un coup, ce qui n'aurait pas de sens au niveau d'un canal.

Ce qui n'est pas implémenté ici, et volontairement : le transfert de propriété,
le départ volontaire du créateur, la suppression du serveur. Aucune de ces trois
opérations n'a de règle arbitrée, et les ouvrir à moitié laisserait un serveur
sans personne pour l'administrer.
"""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, status

from app.chat_schemas import MemberRefIn, ServerCreateIn, ServerOut
from app.chat_store import ChatStore, server_to_out, to_object_id
from app.deps import (
    get_chat_store,
    get_current_user,
    get_store,
    require_csrf,
    require_server_creator,
    require_server_member,
)
from app.store import UserStore

router = APIRouter(tags=["serveurs"])


@router.get("/servers", response_model=list[ServerOut])
async def list_servers(
    user: Annotated[dict[str, Any], Depends(get_current_user)],
    store: Annotated[ChatStore, Depends(get_chat_store)],
) -> list[ServerOut]:
    """Liste les serveurs dont l'appelant est membre.

    La liste est établie depuis `members.user_id`, jamais depuis `created_by` : un
    membre invité doit voir le serveur comme son créateur, et un serveur que
    l'on a seulement créé puis quitté ne doit plus apparaître.
    """
    servers = await store.list_servers_for_user(user["_id"])
    return [await server_to_out(store, server) for server in servers]


@router.post("/servers", response_model=ServerOut, status_code=status.HTTP_201_CREATED)
async def create_server(
    payload: ServerCreateIn,
    _session: Annotated[dict[str, Any], Depends(require_csrf)],
    user: Annotated[dict[str, Any], Depends(get_current_user)],
    store: Annotated[ChatStore, Depends(get_chat_store)],
) -> ServerOut:
    """Crée un serveur dont l'appelant devient le premier membre.

    L'identité du créateur vient de la session, jamais du corps : `ServerCreateIn`
    refuse tout champ inconnu, donc `created_by` et `joined_at` y sont rejetés
    avant d'arriver ici.

    CSRF est exigé, comme sur toute création. `require_public_key` ne l'est pas,
    contrairement à `POST /channels` : un serveur ne détient aucune clé et ne
    chiffre rien par lui-même, il n'a donc rien à emballer. Exiger une clé
    publique ici ne protégerait rien et écarterait un membre parfaitement
    légitime. La règle du canal s'applique au canal, au moment où le salon est
    créé.
    """
    server = await store.create_server(payload.name, user["_id"])
    return await server_to_out(store, server)


@router.get("/servers/{server_id}", response_model=ServerOut)
async def read_server(
    server: Annotated[dict[str, Any], Depends(require_server_member)],
    store: Annotated[ChatStore, Depends(get_chat_store)],
) -> ServerOut:
    """Rend un serveur dont l'appelant est membre.

    L'appartenance est vérifiée par `require_server_member`, qui répond 404 pour
    un identifiant mal formé ou un serveur absent, et 403 pour un tiers. Cette
    route s'appuie dessus au lieu de refaire le contrôle : la règle d'accès est
    écrite une seule fois, et l'ordre des réponses reste celui du projet.

    C'est aussi la source des clés publiques des membres, dont la réponse a besoin
    pour emballer une clé de salon. Elles ne sont donc accessibles qu'à quelqu'un
    qui a déjà le droit de lire le canal.
    """
    return await server_to_out(store, server)


@router.post("/servers/{server_id}/members", response_model=ServerOut)
async def add_server_member(
    server_id: str,
    payload: MemberRefIn,
    _session: Annotated[dict[str, Any], Depends(require_csrf)],
    server: Annotated[dict[str, Any], Depends(require_server_creator)],
    user: Annotated[dict[str, Any], Depends(get_current_user)],
    chat: Annotated[ChatStore, Depends(get_chat_store)],
    store: Annotated[UserStore, Depends(get_store)],
) -> ServerOut:
    """Ajoute un membre au serveur. Réservé au créateur.

    Le membre est désigné par son `username`, que le serveur résout en `user_id`.
    Résoudre côté serveur n'est pas un détail : l'interface ne connaît aucun
    `user_id` tiers — `/auth/me` ne renvoie que le sien — donc lui demander un
    identifiant aurait rendu la route inutilisable depuis l'écran d'adhésion.
    Corollaire : cette route est aussi le seul endroit où un compte peut être
    sondé, et elle est fermée aux tiers.

    Ajouter quelqu'un ne lui donne pas accès au contenu : il lui faudra ensuite
    une enveloppe de clé de salon par canal, que le créateur produit dans son
    navigateur. Le serveur ne peut pas le faire à sa place.

    L'auto-adhésion est refusée : le créateur est déjà membre, et l'accepter
    renverrait un succès sur une opération sans effet. Un serveur n'a pas non
    plus de siège à pourvoir — un membre ordinaire ne peut pas inviter, donc
    s'il n'y a que le créateur, il n'y a rien à inviter.
    """
    # Le motif du nom est volontairement non validé par le schéma : un nom
    # inexistant et un nom malformé doivent répondre la même chose, pour ne pas
    # distinguer « personne ne s'appelle ainsi » de « personne ne peut
    # s'appeler ainsi ».
    target = await store.get_user_by_username(payload.username)
    # La résolution se fait par le nom, mais c'est `get_user_by_id` qui confirme
    # l'appelant : c'est le seul des deux qui écarte un compte désactivé. Un nom
    # qui résout vers un compte désactivé est donc « introuvable » comme un nom
    # inconnu — distinguer les deux révélerait l'existence d'un compte que
    # l'administrateur a choisi de retirer.
    if target is None or await store.get_user_by_id(target["_id"]) is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Utilisateur introuvable.")
    target_id = target["_id"]
    if target_id == user["_id"]:
        raise HTTPException(status.HTTP_409_CONFLICT, "Vous êtes déjà membre de ce serveur.")

    # `add_server_member` est idempotent et filtre sur `members.user_id` : un
    # doublon ne crée pas de second sous-document. Le résultat n'est pas
    # discriminant, et c'est voulu : réinviter quelqu'un déjà membre n'est pas
    # une erreur, c'est un état déjà atteint.
    await chat.add_server_member(server["_id"], target_id)
    refreshed = await chat.get_server(server["_id"])
    return await server_to_out(chat, refreshed or server)


@router.delete("/servers/{server_id}/members/{user_id}", response_model=ServerOut)
async def remove_server_member(
    server_id: str,
    user_id: str,
    _session: Annotated[dict[str, Any], Depends(require_csrf)],
    server: Annotated[dict[str, Any], Depends(require_server_creator)],
    user: Annotated[dict[str, Any], Depends(get_current_user)],
    chat: Annotated[ChatStore, Depends(get_chat_store)],
) -> ServerOut:
    """Retire un membre du serveur. Réservé au créateur.

    Le retrait est plus large qu'avant : il porte sur tous les canaux du serveur,
    pas sur un seul. Le membre perd l'accès à leurs routes et à leur temps réel,
    et conserve les enveloppes qu'il a déjà en local — sans rotation de clé, il
    peut encore déchiffrer ce qui lui parvient.

    Le créateur ne peut pas se retirer. C'est refusé même si d'autres membres
    subsistent, et pas seulement quand il est le dernier : ce n'est pas le nombre
    de membres qui rendrait l'état incohérent, c'est l'absence de créateur, qui
    laisserait le serveur sans personne pour l'administrer.

    Retirer quelqu'un qui n'est pas membre renvoie le serveur inchangé plutôt
    qu'une erreur : c'est le comportement qu'avaient déjà les routes de membres de
    canal, et changer la sémantique ici n'était pas nécessaire.
    """
    target_id = to_object_id(user_id)
    if target_id is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Utilisateur introuvable.")

    if target_id == user["_id"]:
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            "Le créateur ne peut pas quitter son propre serveur : il est le seul à "
            "pouvoir ajouter des membres, créer des canaux et distribuer les clés.",
        )

    await chat.remove_server_member(server["_id"], target_id)
    # Les enveloppes du membre retiré sont supprimées avec son accès. Cela ne
    # retire rien à ce qu'il possède déjà localement, et évite de laisser des
    # enveloppes orphelines qu'il retrouverait s'il réintégrait le serveur.
    await chat.drop_channel_keys_for_server_member(server["_id"], target_id)
    refreshed = await chat.get_server(server["_id"])
    return await server_to_out(chat, refreshed or server)
