"""Persistance des canaux, des enveloppes de clé de salon et des messages.

Aucune méthode de ce module ne déchiffre quoi que ce soit, et aucune ne reçoit
jamais de secret en clair : seules des enveloppes RSA-OAEP et des ciphertexts
AES-GCM y sont écrits.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, Protocol

from bson import ObjectId
from bson.errors import InvalidId
from pymongo.asynchronous.database import AsyncDatabase
from pymongo.errors import DuplicateKeyError

from app.chat_schemas import (
    DEFAULT_HISTORY_LIMIT,
    MAX_HISTORY_LIMIT,
    ChannelOut,
    PublicJwk,
    ServerMemberOut,
    ServerOut,
)


def to_object_id(value: str) -> ObjectId | None:
    """Convertit un identifiant en `ObjectId`, ou renvoie `None` si invalide.

    Ce passage explicite est ce qui empêche un corps de requête de contenir un
    objet là où l'API attend un identifiant : sans lui, un dictionnaire deviendrait
    un filtre MongoDB.
    """
    try:
        return ObjectId(value)
    except (InvalidId, TypeError):
        return None


def resolve_limit(limit: int | None) -> int:
    """Borne la taille d'une page d'historique."""
    if limit is None:
        return DEFAULT_HISTORY_LIMIT
    return max(1, min(limit, MAX_HISTORY_LIMIT))


class ChatStore(Protocol):
    """Opérations nécessaires à la messagerie chiffrée."""

    async def create_channel(
        self, name: str, server_id: ObjectId, client_ref: str
    ) -> dict[str, Any]: ...

    async def get_channel(self, channel_id: ObjectId) -> dict[str, Any] | None: ...

    async def list_channels_for_servers(
        self, server_ids: list[ObjectId]
    ) -> list[dict[str, Any]]: ...

    async def list_channels_for_user(self, user_id: ObjectId) -> list[dict[str, Any]]: ...

    async def set_channel_key(
        self, channel_id: ObjectId, user_id: ObjectId, wrapped_key: str
    ) -> bool: ...

    async def get_channel_key(
        self, channel_id: ObjectId, user_id: ObjectId
    ) -> dict[str, Any] | None: ...

    async def drop_channel_keys_for_server_member(
        self, server_id: ObjectId, user_id: ObjectId
    ) -> int: ...

    async def insert_message(
        self,
        channel_id: ObjectId,
        sender_id: ObjectId,
        client_id: str,
        ciphertext: str,
        iv: str,
    ) -> dict[str, Any]: ...

    async def list_messages(
        self, channel_id: ObjectId, before: ObjectId | None, limit: int
    ) -> list[dict[str, Any]]: ...

    async def users_by_ids(self, user_ids: list[ObjectId]) -> dict[ObjectId, dict[str, Any]]: ...

    async def create_server(self, name: str, created_by: ObjectId) -> dict[str, Any]: ...

    async def get_server(self, server_id: ObjectId) -> dict[str, Any] | None: ...

    async def list_servers_for_user(self, user_id: ObjectId) -> list[dict[str, Any]]: ...

    async def add_server_member(self, server_id: ObjectId, user_id: ObjectId) -> bool: ...

    async def remove_server_member(self, server_id: ObjectId, user_id: ObjectId) -> int: ...

    async def is_server_member(self, server_id: ObjectId, user_id: ObjectId) -> bool: ...

    async def oldest_server_member(self, server_id: ObjectId) -> dict[str, Any] | None: ...


class MongoChatStore:
    """Implémentation MongoDB de `ChatStore`."""

    def __init__(self, database: AsyncDatabase) -> None:
        self._channels = database.channels
        self._channel_keys = database.channel_keys
        self._messages = database.messages
        self._users = database.users
        self._servers = database.servers

    async def create_channel(
        self, name: str, server_id: ObjectId, client_ref: str
    ) -> dict[str, Any]:
        """Crée un canal dans un serveur.

        Le canal ne porte ni `members` ni `created_by` : l'appartenance et
        l'autorité d'administration appartiennent au serveur parent, et les dupliquer
        ici créerait deux vérités à tenir synchronisées. Un canal ne sait pas
        qui peut le lire ; il sait seulement de quel serveur il dépend.
        """
        document = {
            "name": name,
            "server_id": server_id,
            "created_at": datetime.now(UTC),
            "client_ref": str(client_ref),
        }
        result = await self._channels.insert_one(document)
        document["_id"] = result.inserted_id
        return document

    async def get_channel(self, channel_id: ObjectId) -> dict[str, Any] | None:
        return await self._channels.find_one({"_id": channel_id})

    async def list_channels_for_servers(self, server_ids: list[ObjectId]) -> list[dict[str, Any]]:
        """Canaux d'une liste de serveurs, du plus ancien au plus récent."""
        if not server_ids:
            return []
        cursor = self._channels.find({"server_id": {"$in": server_ids}}).sort("created_at", 1)
        return await cursor.to_list(None)

    async def list_channels_for_user(self, user_id: ObjectId) -> list[dict[str, Any]]:
        """Canaux de tous les serveurs dont l'utilisateur est membre.

        L'autorisation porte sur le serveur, jamais sur le canal : on relève
        d'abord les serveurs de l'utilisateur, puis on ne retient que les canaux
        qui en dépendent. Aucun filtre ne porte sur une membership de canal,
        puisque cette notion n'existe plus.
        """
        servers = self._servers.find({"members.user_id": user_id}, {"_id": 1})
        server_ids = [server["_id"] async for server in servers]
        return await self.list_channels_for_servers(server_ids)

    async def set_channel_key(
        self, channel_id: ObjectId, user_id: ObjectId, wrapped_key: str
    ) -> bool:
        """Dépose une enveloppe. Renvoie `True` si elle est nouvelle.

        Un dépôt répété est traité comme un succès : après une reconnexion, le
        client ne peut pas savoir si sa première tentative est arrivée. La
        version de clé vaut 1 pour tout le MVP, il n'existe donc jamais plus
        d'une enveloppe par couple (canal, utilisateur).
        """
        try:
            await self._channel_keys.insert_one(
                {
                    "channel_id": channel_id,
                    "user_id": user_id,
                    "key_version": 1,
                    "wrapped_key": wrapped_key,
                    "created_at": datetime.now(UTC),
                }
            )
        except DuplicateKeyError:
            return False
        return True

    async def get_channel_key(
        self, channel_id: ObjectId, user_id: ObjectId
    ) -> dict[str, Any] | None:
        return await self._channel_keys.find_one(
            {"channel_id": channel_id, "user_id": user_id, "key_version": 1}
        )

    async def drop_channel_keys_for_server_member(
        self, server_id: ObjectId, user_id: ObjectId
    ) -> int:
        """Supprime toutes les enveloppes d'un membre sur les canaux d'un serveur.

        Conservé depuis l'époque des membres de canal, où un retrait ne
        concernait qu'un canal. Le retrait étant devenu une opération de serveur,
        elle porte sur tous ses canaux d'un coup.

        L'accès est de toute façon déjà fermé par la dépendance d'autorisation,
        qui contrôle le serveur parent avant d'atteindre les enveloppes. Ce n'est
        donc pas ce retrait qui protège : c'est ce qui évite de laisser des
        enveloppes orphelines derrière un membre parti, et de les rendre
        relisibles s'il réintégrait un jour le serveur.

        Les canaux sont d'abord relevés parce que `channel_keys` ne connaît que
        `channel_id` : il n'existe aucun chemin de requête qui mène à « toutes les
        enveloppes d'un serveur », et un `$lookup` serait disproportionné ici. La
        liste tient en mémoire, un serveur comptant quelques dizaines de canaux.
        """
        channel_ids = [
            channel["_id"]
            async for channel in self._channels.find({"server_id": server_id}, {"_id": 1})
        ]
        if not channel_ids:
            return 0
        result = await self._channel_keys.delete_many(
            {"channel_id": {"$in": channel_ids}, "user_id": user_id}
        )
        return int(result.deleted_count)

    async def insert_message(
        self,
        channel_id: ObjectId,
        sender_id: ObjectId,
        client_id: str,
        ciphertext: str,
        iv: str,
    ) -> dict[str, Any]:
        """Enregistre un message et renvoie le document complet.

        Les champs sont énumérés explicitement plutôt que reçus comme un document
        libre : un appelant ne peut ainsi pas glisser un champ supplémentaire,
        et en particulier substituer un `sender_id` à celui de la session.

        L'unicité de (sender_id, client_id) assure l'anti-rejeu : un client ne
        peut pas faire enregistrer deux fois le même message. L'expéditeur étant
        déduit de la session, un tiers ne peut pas rejouer une trame capturée en
        changeant d'expéditeur.
        """
        document = {
            "channel_id": channel_id,
            "sender_id": sender_id,
            "client_id": client_id,
            "ciphertext": ciphertext,
            "iv": iv,
            "created_at": datetime.now(UTC),
        }
        result = await self._messages.insert_one(document)
        stored = await self._messages.find_one({"_id": result.inserted_id})
        return stored or {}

    async def list_messages(
        self, channel_id: ObjectId, before: ObjectId | None, limit: int
    ) -> list[dict[str, Any]]:
        query: dict[str, Any] = {"channel_id": channel_id}
        if before is not None:
            query["_id"] = {"$lt": before}
        cursor = self._messages.find(query).sort("_id", -1).limit(limit)
        found = await cursor.to_list(None)
        # Le curseur parcourt du plus récent au plus ancien, l'API rend ensuite
        # les messages dans l'ordre de lecture.
        found.reverse()
        return found

    async def users_by_ids(self, user_ids: list[ObjectId]) -> dict[ObjectId, dict[str, Any]]:
        """Charge les profils correspondant à une liste d'identifiants."""
        if not user_ids:
            return {}
        cursor = self._users.find({"_id": {"$in": user_ids}}, {"username": 1, "public_key": 1})
        return {document["_id"]: document async for document in cursor}

    async def create_server(self, name: str, created_by: ObjectId) -> dict[str, Any]:
        """Crée un serveur dont l'appelant est le premier membre.

        Le créateur entre dans `members` avec le même `joined_at` que
        `created_at` : il est, par construction, le membre le plus ancien, et
        donc le successeur par défaut le jour où quelqu'un lui transfère le
        rôle. Un seul horodatage est produit pour les deux, ce qui évite qu'un
        serveur naisse avec un créateur qui ne le serait pas encore.

        `created_by` et le `user_id` du premier membre proviennent tous deux de
        la session : le magasin ne les déduit pas, il les reçoit, et c'est la
        route qui les tient de `get_current_user`.
        """
        now = datetime.now(UTC)
        document = {
            "name": name,
            "created_by": created_by,
            "created_at": now,
            "members": [{"user_id": created_by, "joined_at": now}],
        }
        result = await self._servers.insert_one(document)
        document["_id"] = result.inserted_id
        return document

    async def get_server(self, server_id: ObjectId) -> dict[str, Any] | None:
        return await self._servers.find_one({"_id": server_id})

    async def list_servers_for_user(self, user_id: ObjectId) -> list[dict[str, Any]]:
        """Serveurs dont l'utilisateur est membre, du plus ancien au plus récent.

        Le filtre porte sur `members.user_id` et non sur `members` : les membres
        étant des sous-documents, c'est le chemin du sous-champ qui identifie la
        personne. Filtrer sur `members` entier ne correspondrait pas à une
        appartenance.
        """
        cursor = self._servers.find({"members.user_id": user_id}).sort("created_at", 1)
        return await cursor.to_list(None)

    async def add_server_member(self, server_id: ObjectId, user_id: ObjectId) -> bool:
        """Ajoute un membre. Renvoie `True` si l'ajout a eu lieu.

        `$addToSet` ne convient pas ici. L'identité d'un membre est
        `members.user_id`, alors que le sous-document poussé contient aussi
        `joined_at` : deux sous-documents pour la même personne seraient
        différents, donc tous deux acceptés, et `members` se remplirait de
        doublons. L'identité est donc portée par le filtre, et le `$push` n'a
        lieu que si l'absence est constatée dans la même opération atomique.

        Renvoie `False` si le membre était déjà là : l'appel est idempotent, et
        l'indication est décisive — `matched_count` ne la dirait pas, un filtre
        qui ne matche pas est indiscernable d'un serveur absent.
        """
        result = await self._servers.update_one(
            {"_id": server_id, "members.user_id": {"$ne": user_id}},
            {"$push": {"members": {"user_id": user_id, "joined_at": datetime.now(UTC)}}},
        )
        return result.modified_count == 1

    async def remove_server_member(self, server_id: ObjectId, user_id: ObjectId) -> int:
        """Retire un membre du serveur. Renvoie le nombre de retraits effectués.

        `$pull` est atomique et sans danger ici : retirer deux fois le même
        membre ne fait que remplacer un `$pull` sans effet, et l'appel est donc
        idempotent. Renvoyer le nombre de retraits effectif permet à l'appelant
        de distinguer « retiré » de « n'était pas membre ».

        Retirer quelqu'un d'un serveur le retire de tous ses canaux d'un coup : les
        canaux n'ont pas de liste de membres, donc aucune copie ne subsiste
        ailleurs de son appartenance.
        """
        result = await self._servers.update_one(
            {"_id": server_id}, {"$pull": {"members": {"user_id": user_id}}}
        )
        return int(result.modified_count)

    async def is_server_member(self, server_id: ObjectId, user_id: ObjectId) -> bool:
        return (
            await self._servers.count_documents(
                {"_id": server_id, "members.user_id": user_id}, limit=1
            )
            > 0
        )

    async def oldest_server_member(self, server_id: ObjectId) -> dict[str, Any] | None:
        """Membre le plus ancien du serveur, ou `None` s'il n'en a aucun.

        L'ancienneté se lit dans `joined_at`, jamais dans l'ordre du tableau :
        deux membres peuvent être insérés dans un ordre qui ne reflète pas leur
        adhésion réelle, et seul l'horodatage fait foi.

        Le tri se fait en Python plutôt que par `$sortArray` : un serveur compte
        quelques dizaines de membres, et l'appelant dispose le plus souvent du
        document complet, qu'il a chargé pour vérifier l'appartenance. Une
        projection `{members: 1}` évite de ramener le reste, et le minimum est
        immédiat.
        """
        server = await self._servers.find_one({"_id": server_id}, {"members": 1})
        if server is None:
            return None
        members = server.get("members") or []
        if not members:
            return None
        return min(members, key=lambda member: member["joined_at"])


def channel_to_out(channel: dict[str, Any]) -> ChannelOut:
    """Construit la représentation d'un canal.

    Le canal ne renvoie ni membres ni propriétaire : il ne les possède pas. La
    liste des membres et l'autorité d'administration appartiennent au serveur
    parent, atteint par `server_id`. Recopier ces informations ici créerait une
    seconde version de l'appartenance, exactement ce que la migration supprime —
    et l'interface irait chercher l'information à un endroit, l'autorisation
    la vérifierait à un autre.
    """
    return ChannelOut(
        id=str(channel["_id"]),
        name=channel["name"],
        server_id=str(channel["server_id"]),
        created_at=channel["created_at"],
        client_ref=channel["client_ref"],
    )


async def server_to_out(chat: ChatStore, server: dict[str, Any]) -> ServerOut:
    """Construit la représentation d'un serveur, avec ses membres et empreintes.

    Même principe que `channel_to_out`, et pour la même raison : les profils sont
    chargés d'un coup, par identifiants, avec une projection explicite qui
    exclut le haché du mot de passe. Rien d'autre n'est lu dans la collection
    `users`, et un serveur ne contient aucun secret : ni clé de salon, ni clé
    privée, ni texte chiffré.

    L'ordre des membres est celui du tableau, c'est-à-dire l'ordre d'adhésion.
    C'est `joined_at` qui fait foi, et il est exposé pour que l'interface puisse
    le vérifier.
    """
    members: list[Any] = list(server.get("members", []))
    profiles = await chat.users_by_ids([member["user_id"] for member in members])
    rendered = []
    for member in members:
        member_id = member["user_id"]
        profile = profiles.get(member_id, {})
        public_key = profile.get("public_key") or {}
        rendered.append(
            ServerMemberOut(
                user_id=str(member_id),
                username=profile.get("username", ""),
                joined_at=member["joined_at"],
                public_key_fingerprint=public_key.get("fingerprint"),
                public_key_jwk=(
                    PublicJwk.model_validate(public_key["jwk"]) if public_key.get("jwk") else None
                ),
            )
        )
    return ServerOut(
        id=str(server["_id"]),
        name=server["name"],
        created_at=server["created_at"],
        created_by=str(server["created_by"]),
        members=rendered,
    )
