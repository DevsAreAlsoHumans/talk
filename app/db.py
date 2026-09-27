"""Client MongoDB partagé et création des index au démarrage.

`AsyncMongoClient` se lie à la boucle asyncio qui l'a créé : un client ne peut
donc pas être partagé entre deux boucles. La suite de tests en découle, elle
n'emploie qu'un seul `TestClient` (donc un seul portal) et isole les sessions en
manipulant le cookie jar plutôt qu'en ouvrant un second client.
"""

from __future__ import annotations

from pymongo import AsyncMongoClient
from pymongo.asynchronous.database import AsyncDatabase

from app.config import get_settings

_client: AsyncMongoClient | None = None


def get_client() -> AsyncMongoClient:
    """Retourne le client asynchrone, en le créant au premier appel."""
    global _client
    if _client is None:
        _client = AsyncMongoClient(get_settings().mongo_url, tz_aware=True)
    return _client


def get_db() -> AsyncDatabase:
    """Dépendance FastAPI : base de données courante."""
    return get_client()[get_settings().mongo_db_name]


async def ensure_indexes(database: AsyncDatabase) -> None:
    """Crée les index nécessaires à l'unicité, à l'expiration et aux curseurs.

    L'index unique sur `username` est ce qui rend fiable la gestion des
    inscriptions concurrentes : sans lui, deux requêtes simultanées pourraient
    valider le même nom avant qu'aucune contrainte ne soit en place.
    """
    await database.users.create_index("username", unique=True)
    await database.sessions.create_index("token_hash", unique=True)
    # Purge automatique des sessions expirées par le moniteur TTL de MongoDB.
    await database.sessions.create_index("expires_at", expireAfterSeconds=0)

    # Un utilisateur ne possède qu'un canal pour une référence locale donnée :
    # c'est ce qui permet de retrouver un canal créé juste avant une fermeture
    # du navigateur, sans ambiguïté.
    await database.channels.create_index([("created_by", 1), ("client_ref", 1)], unique=True)
    # Recherche des canaux d'un membre.
    await database.channels.create_index("members")
    # Une seule enveloppe par couple (canal, destinataire) dans le MVP.
    await database.channel_keys.create_index(
        [("channel_id", 1), ("user_id", 1), ("key_version", 1)], unique=True
    )
    # Anti-rejeu : un expéditeur ne peut pas enregistrer deux fois le même
    # message, et `key_version` permet de retrouver une enveloppe précise.
    await database.messages.create_index([("sender_id", 1), ("client_id", 1)], unique=True)
    # Pagination de l'historique par curseur décroissant.
    await database.messages.create_index([("channel_id", 1), ("_id", -1)])


async def close_client() -> None:
    """Ferme le client et libère le pool de connexions."""
    global _client
    if _client is not None:
        await _client.close()
        _client = None
