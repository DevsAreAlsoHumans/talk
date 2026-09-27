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
    MemberOut,
    PublicJwk,
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
        self, name: str, created_by: ObjectId, client_ref: str
    ) -> dict[str, Any]: ...

    async def get_channel(self, channel_id: ObjectId) -> dict[str, Any] | None: ...

    async def list_channels_for_user(self, user_id: ObjectId) -> list[dict[str, Any]]: ...

    async def get_channel_by_client_ref(
        self, user_id: ObjectId, client_ref: str
    ) -> dict[str, Any] | None: ...

    async def add_member(self, channel_id: ObjectId, user_id: ObjectId) -> None: ...

    async def remove_member(self, channel_id: ObjectId, user_id: ObjectId) -> int: ...

    async def is_member(self, channel_id: ObjectId, user_id: ObjectId) -> bool: ...

    async def set_channel_key(
        self, channel_id: ObjectId, user_id: ObjectId, wrapped_key: str
    ) -> bool: ...

    async def get_channel_key(
        self, channel_id: ObjectId, user_id: ObjectId
    ) -> dict[str, Any] | None: ...

    async def drop_channel_key(self, channel_id: ObjectId, user_id: ObjectId) -> None: ...

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


class MongoChatStore:
    """Implémentation MongoDB de `ChatStore`."""

    def __init__(self, database: AsyncDatabase) -> None:
        self._channels = database.channels
        self._channel_keys = database.channel_keys
        self._messages = database.messages
        self._users = database.users

    async def create_channel(
        self, name: str, created_by: ObjectId, client_ref: str
    ) -> dict[str, Any]:
        document = {
            "name": name,
            "created_by": created_by,
            "created_at": datetime.now(UTC),
            "client_ref": str(client_ref),
            "members": [created_by],
        }
        result = await self._channels.insert_one(document)
        document["_id"] = result.inserted_id
        return document

    async def get_channel(self, channel_id: ObjectId) -> dict[str, Any] | None:
        return await self._channels.find_one({"_id": channel_id})

    async def list_channels_for_user(self, user_id: ObjectId) -> list[dict[str, Any]]:
        cursor = self._channels.find({"members": user_id}).sort("created_at", 1)
        return await cursor.to_list(None)

    async def get_channel_by_client_ref(
        self, user_id: ObjectId, client_ref: str
    ) -> dict[str, Any] | None:
        """Retrouve un canal à partir de la référence locale du navigateur.

        C'est ce qui permet de reprendre après une fermeture inattendue du
        navigateur : le client retrouve le canal qu'il a réussi à créer et y
        dépose l'enveloppe qui manquait.
        """
        return await self._channels.find_one({"created_by": user_id, "client_ref": str(client_ref)})

    async def add_member(self, channel_id: ObjectId, user_id: ObjectId) -> None:
        await self._channels.update_one({"_id": channel_id}, {"$addToSet": {"members": user_id}})

    async def remove_member(self, channel_id: ObjectId, user_id: ObjectId) -> int:
        result = await self._channels.update_one(
            {"_id": channel_id}, {"$pull": {"members": user_id}}
        )
        return int(result.modified_count)

    async def is_member(self, channel_id: ObjectId, user_id: ObjectId) -> bool:
        return (
            await self._channels.count_documents({"_id": channel_id, "members": user_id}, limit=1)
            > 0
        )

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

    async def drop_channel_key(self, channel_id: ObjectId, user_id: ObjectId) -> None:
        """Supprime l'enveloppe d'un membre qui n'a plus accès au canal."""
        await self._channel_keys.delete_one({"channel_id": channel_id, "user_id": user_id})

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


async def channel_to_out(chat: ChatStore, channel: dict[str, Any]) -> ChannelOut:
    """Construit la représentation d'un canal, avec ses membres et empreintes.

    Seules des données publiques sont exposées : identifiant, nom d'utilisateur
    et empreinte de clé. Le haché du mot de passe n'est jamais chargé ici, la
    projection de `users_by_ids` l'exclut explicitement.
    """
    member_ids: list[Any] = list(channel.get("members", []))
    profiles = await chat.users_by_ids(member_ids)
    members = []
    for member_id in member_ids:
        profile = profiles.get(member_id, {})
        public_key = profile.get("public_key") or {}
        members.append(
            MemberOut(
                id=str(member_id),
                username=profile.get("username", ""),
                public_key_fingerprint=public_key.get("fingerprint"),
                # La clé publique est rendue pour qu'un membre puisse emballer
                # la clé de salon à destination d'un autre. Un membre qui n'a pas
                # encore publié de clé apparaît avec `public_key_jwk` à `null`,
                # ce qui est un état normal et non une erreur.
                public_key_jwk=(
                    PublicJwk.model_validate(public_key["jwk"]) if public_key.get("jwk") else None
                ),
            )
        )
    return ChannelOut(
        id=str(channel["_id"]),
        name=channel["name"],
        created_at=channel["created_at"],
        client_ref=channel["client_ref"],
        created_by=str(channel["created_by"]),
        members=members,
    )
