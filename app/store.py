"""Persistance des utilisateurs et des sessions.

`UserStore` décrit ce dont l'authentification a besoin ; `MongoUserStore` en est
l'implémentation. Les requêtes sont construites à partir de valeurs déjà
validées par Pydantic et converties par `hash_token` : aucun fragment d'entrée
utilisateur n'est jamais interprété comme un opérateur MongoDB.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any, Protocol

from pymongo.asynchronous.database import AsyncDatabase
from pymongo.errors import DuplicateKeyError

from app.config import get_settings
from app.security import generate_token, hash_token


class DuplicateUsernameError(Exception):
    """Levée lorsqu'un nom d'utilisateur est déjà pris."""


# Le MVP interdit le remplacement d'une clé publique : `key_version` reste donc
# à 1 en permanence. Toute évolution future devra s'accompagner d'une procédure de
# ré-emballage de toutes les enveloppes existantes.
PUBLIC_KEY_VERSION = 1


@dataclass(frozen=True)
class NewSession:
    """Jetons en clair d'une session fraîchement créée.

    Le jeton de session n'est stocké que sous forme d'empreinte : cet objet le
    transporte le temps de la réponse HTTP, puis il est oublié.
    """

    token: str
    csrf_token: str
    expires_at: datetime


class UserStore(Protocol):
    """Opérations minimales nécessaires à l'authentification."""

    async def create_user(self, username: str, password_hash: str) -> dict[str, Any]: ...

    async def get_user_by_username(self, username: str) -> dict[str, Any] | None: ...

    async def create_anonymous_session(self) -> NewSession: ...

    async def create_user_session(self, user_id: Any) -> NewSession: ...

    async def get_session(self, token: str) -> dict[str, Any] | None: ...

    async def delete_session_by_hash(self, token_hash: str) -> None: ...

    async def get_user_by_session(self, token: str) -> dict[str, Any] | None: ...

    async def get_user_by_id(self, user_id: Any) -> dict[str, Any] | None: ...

    async def get_public_key(self, user_id: Any) -> dict[str, Any] | None: ...

    async def save_public_key(
        self, user_id: Any, jwk: dict[str, Any], fingerprint: str
    ) -> bool: ...


class MongoUserStore:
    """Implémentation MongoDB de `UserStore`."""

    def __init__(self, database: AsyncDatabase) -> None:
        self._users = database.users
        self._sessions = database.sessions

    async def create_user(self, username: str, password_hash: str) -> dict[str, Any]:
        document = {
            "username": username,
            "password_hash": password_hash,
            "created_at": datetime.now(UTC),
            "disabled": False,
        }
        try:
            result = await self._users.insert_one(document)
        except DuplicateKeyError as exc:
            raise DuplicateUsernameError(username) from exc
        document["_id"] = result.inserted_id
        return document

    async def get_user_by_username(self, username: str) -> dict[str, Any] | None:
        return await self._users.find_one({"username": username})

    async def create_anonymous_session(self) -> NewSession:
        return await self._create_session(None)

    async def create_user_session(self, user_id: Any) -> NewSession:
        return await self._create_session(user_id)

    async def _create_session(self, user_id: Any) -> NewSession:
        settings = get_settings()
        if user_id is None:
            ttl = settings.anonymous_session_ttl_seconds
        else:
            ttl = settings.session_ttl_seconds
        now = datetime.now(UTC)
        expires_at = now + timedelta(seconds=ttl)
        token = generate_token()
        csrf_token = generate_token()
        await self._sessions.insert_one(
            {
                "token_hash": hash_token(token),
                "user_id": user_id,
                "csrf_token": csrf_token,
                "created_at": now,
                "expires_at": expires_at,
                "last_seen_at": now,
            }
        )
        return NewSession(token=token, csrf_token=csrf_token, expires_at=expires_at)

    async def get_session(self, token: str) -> dict[str, Any] | None:
        # L'expiration est vérifiée ici et pas seulement par l'index TTL : le
        # moniteur de MongoDB ne purge que périodiquement, un document périmé
        # peut donc être lu entre deux passages.
        return await self._sessions.find_one(
            {"token_hash": hash_token(token), "expires_at": {"$gt": datetime.now(UTC)}}
        )

    async def delete_session_by_hash(self, token_hash: str) -> None:
        await self._sessions.delete_one({"token_hash": token_hash})

    async def get_user_by_session(self, token: str) -> dict[str, Any] | None:
        session = await self.get_session(token)
        if session is None or session.get("user_id") is None:
            return None
        return await self._users.find_one({"_id": session["user_id"], "disabled": False})

    async def get_user_by_id(self, user_id: Any) -> dict[str, Any] | None:
        return await self._users.find_one({"_id": user_id, "disabled": False})

    async def get_public_key(self, user_id: Any) -> dict[str, Any] | None:
        """Renvoie la clé publique enregistrée, ou `None` si l'utilisateur n'en a pas.

        La projection est explicite : ni le haché du mot de passe, ni une
        éventuelle clé privée ne peuvent se retrouver par erreur dans la valeur
        renvoyée au routeur.
        """
        return await self._users.find_one(
            {"_id": user_id, "disabled": False}, {"public_key": 1, "username": 1}
        )

    async def save_public_key(self, user_id: Any, jwk: dict[str, Any], fingerprint: str) -> bool:
        """Enregistre la clé publique, uniquement si le compte n'en possède pas.

        Renvoie `True` si c'est cet appel qui a écrit la clé, `False` si le
        document en possédait déjà une. C'est `matched_count` qui porte cette
        information, et la remontée n'est pas cosmétique : le filtre
        `{"public_key": {"$exists": False}}` rend l'écriture atomique, donc
        déterminante, mais silencieuse. Deux publications concurrentes ne
        peuvent pas s'écraser, et il appartient au routeur — seul lieu qui
        connaît le contexte de la requête — de dire à un perdant que sa clé
        n'a pas été enregistrée.

        L'idempotence et le refus de remplacement restent appliqués au niveau du
        routeur, qui doit pouvoir distinguer « pas encore de clé » de « clé
        différente », deux cas que cet upsert ne voit pas.
        """
        result = await self._users.update_one(
            {"_id": user_id, "public_key": {"$exists": False}},
            {
                "$set": {
                    "public_key": {
                        "jwk": jwk,
                        "fingerprint": fingerprint,
                        "version": PUBLIC_KEY_VERSION,
                        "updated_at": datetime.now(UTC),
                    }
                }
            },
        )
        return result.matched_count == 1
