"""Client MongoDB partagé et création des index au démarrage.

`AsyncMongoClient` se lie à la boucle asyncio qui l'a créé : un client ne peut
donc pas être partagé entre deux boucles. La suite de tests en découle, elle
n'emploie qu'un seul `TestClient` (donc un seul portal) et isole les sessions en
manipulant le cookie jar plutôt qu'en ouvrant un second client.
"""

from __future__ import annotations

from pymongo import AsyncMongoClient
from pymongo.asynchronous.database import AsyncDatabase
from pymongo.errors import OperationFailure

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


async def _drop_obsolete_indexes(database: AsyncDatabase, collection: str, *names: str) -> None:
    """Supprime les index devenus inutiles, sans échouer s'ils n'existent pas.

    `create_index` n'ajoute rien et ne retire rien : un index devenu faux après un
    changement de modèle reste en place indéfiniment. C'est ici que ça devient
    nuisible, et gravement.

    L'ancien index unique `(created_by, client_ref)` en est l'exemple. Un canal
    n'écrit plus `created_by` ; dans un index composé, un champ absent est indexé
    comme `null`. Toutes les lignes se retrouvent donc avec la même première
    clé, et la contrainte se réduit à « `client_ref` est unique dans toute la
    base ». Le même `client_ref` dans deux serveurs distincts — parfaitement
    légitime, et le cas courant d'un onglet ouvert deux fois — se voit alors
    refuser avec un 409 trompeur. Créer le nouvel index ne suffit pas : il faut
    retirer l'ancien.

    Aucun `OperationFailure` n'est toléré en dehors de « index absent » : une
    autre erreur, des permissions par exemple, doit remonter plutôt que d'être
    avalée en silence.
    """
    for name in names:
        try:
            await database[collection].drop_index(name)
        except OperationFailure as exc:
            if exc.code in (27, 26):  # IndexNotFound, NamespaceNotFound
                continue
            raise


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

    # Index devenus faux après le déplacement de l'appartenance vers le serveur.
    # Voir `_drop_obsolete_indexes` : sans cela, l'ancien index unique dégrade la
    # contrainte de `client_ref` à une unicité globale.
    await _drop_obsolete_indexes(database, "channels", "created_by_1_client_ref_1", "members_1")

    # Un serveur ne porte qu'un canal pour une référence locale donnée : c'est ce
    # qui permet de retrouver un canal créé juste avant une fermeture du
    # navigateur, sans ambiguïté. Le canal est identifié par son serveur parent,
    # pas par son auteur : deux membres du même serveur qui créeraient un canal
    # avec la même référence locale entrent en collision, ce qui est le
    # comportement voulu — la référence locale est celle du serveur, et seul le
    # créateur du serveur peut en créer un.
    await database.channels.create_index([("server_id", 1), ("client_ref", 1)], unique=True)
    # Canaux d'un serveur : la liste hiérarchique, et le premier terme de la
    # requête de `list_channels_for_user` après relevé des serveurs du membre.
    await database.channels.create_index("server_id")
    # Serveurs d'un membre. Le chemin du sous-champ, et non `members` : les
    # membres d'un serveur sont des sous-documents, et c'est leur `user_id` qui
    # identifie la personne. Un index sur `members` entier indexerait des paires
    # `{user_id, joined_at}` changeantes — `joined_at` diffère pour tout nouvel
    # arrivant — donc inutilisables pour retrouver les serveurs d'un membre.
    await database.servers.create_index("members.user_id")
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
