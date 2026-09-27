"""Fixtures partagées : application, isolation d'état et aide aux tests.

L'environnement est renseigné *avant* l'import de `app.main` : la configuration
étant mise en cache au premier usage, les tests voient toujours la même.

Les tests sont des tests d'intégration : ils s'exécutent contre le vrai MongoDB
démarré par `docker compose run --rm test`. L'isolation se fait en purgeant les
collections et le cookie jar entre chaque test, ce qui préserve les index
(contrairement à `drop_database`, qui les supprimerait).

Un seul `TestClient` est partagé par tous les tests : `AsyncMongoClient` étant lié
à sa boucle asyncio, un second client créerait une seconde boucle et le premier
usage de la base échouerait. Les sessions croisées sont donc obtenues en vidant
le cookie jar entre deux appels, plutôt qu'en ouvrant un second client.
"""

from __future__ import annotations

import base64
import os
import uuid
from collections.abc import Iterator

os.environ.setdefault("MONGO_URL", "mongodb://mongo:27017")
os.environ.setdefault("MONGO_DB_NAME", "talk_test")
os.environ.setdefault("ENV", "development")
os.environ.setdefault("APP_ORIGINS", "http://testserver,https://testserver,http://localhost:8000")

import pytest
from bson import ObjectId
from fastapi.testclient import TestClient
from pymongo import MongoClient

from app.config import CSRF_HEADER_NAME, SESSION_COOKIE_NAME, get_settings
from app.main import app

TEST_ORIGIN = "http://testserver"
VALID_PASSWORD = "mot-de-passe-solide-42"


def unique_username(prefix: str = "user") -> str:
    """Nom d'utilisateur inédit, pour que les tests ne se marchent pas dessus."""
    return f"{prefix}_{uuid.uuid4().hex[:10]}"


def sync_database() -> MongoClient:
    """Client synchrone : suffisant pour nettoyer et inspecter la base.

    `tz_aware=True` comme le client de l'application (`app/db.py`) : la base
    stocke de l'UTC, et un datetime sans fuseau ne se compare pas à un datetime
    avec fuseau — la première comparaison lève un `TypeError`. Observer la même
    réalité que l'application évite qu'un test valide un horodatage que le code ne
    verra jamais tel quel.
    """
    return MongoClient(get_settings().mongo_url, serverSelectionTimeoutMS=10000, tz_aware=True)


def purge_database() -> None:
    mongo = sync_database()
    try:
        database = mongo[get_settings().mongo_db_name]
        database.sessions.delete_many({})
        database.users.delete_many({})
        database.channels.delete_many({})
        database.channel_keys.delete_many({})
        database.messages.delete_many({})
        database.servers.delete_many({})
    finally:
        mongo.close()


@pytest.fixture(scope="session")
def client() -> Iterator[TestClient]:
    # Le contexte est indispensable : c'est lui qui exécute le lifespan de
    # l'application, donc la création des index MongoDB.
    with TestClient(app) as test_client:
        yield test_client


@pytest.fixture(autouse=True)
def isolated_state(client: TestClient) -> Iterator[None]:
    """Vide le cookie jar et la base avant et après chaque test."""
    client.cookies.clear()
    purge_database()
    yield
    client.cookies.clear()
    purge_database()


def csrf_headers(client: TestClient) -> dict[str, str]:
    """En-têtes d'une mutation, jeton CSRF inclus."""
    response = client.get("/auth/csrf")
    assert response.status_code == 200, response.text
    return {CSRF_HEADER_NAME: response.json()["csrf_token"]}


def register_user(
    client: TestClient,
    username: str | None = None,
    password: str = VALID_PASSWORD,
) -> str:
    """Inscrit un utilisateur et laisse le client connecté."""
    chosen = username or unique_username()
    response = client.post(
        "/auth/register",
        json={"username": chosen, "password": password},
        headers=csrf_headers(client),
    )
    assert response.status_code == 201, response.text
    return chosen


def login_user(client: TestClient, username: str, password: str = VALID_PASSWORD) -> str:
    """Reconnecte un utilisateur déjà inscrit, et laisse le client connecté."""
    response = client.post(
        "/auth/login",
        json={"username": username, "password": password},
        headers=csrf_headers(client),
    )
    assert response.status_code == 200, response.text
    return username


def session_cookie(client: TestClient) -> str | None:
    return client.cookies.get(SESSION_COOKIE_NAME)


def set_cookie_attributes(response: object, cookie_name: str) -> str:
    """Retourne l'en-tête `Set-Cookie` brut correspondant à un cookie donné.

    Les attributs (`HttpOnly`, `SameSite`, `Secure`) n'existent que dans l'en-tête
    brut : le cookie jar les a déjà digérés.
    """
    headers = response.headers  # type: ignore[attr-defined]
    raw_headers = headers.get_list("set-cookie")
    for header in raw_headers:
        if header.startswith(f"{cookie_name}="):
            return header
    raise AssertionError(f"Set-Cookie absent pour {cookie_name} : {raw_headers}")


def public_jwk(seed: int = 0) -> dict[str, str]:
    """Clé publique RSA-2048 synthétique, conforme au schéma de validation.

    Aucun module n'implémente RSA côté Python, et il n'en faut pas : le serveur
    ne manipule que des formes. Le module est donc une suite de 256 octets, ce que
    la validation exige, sans être un vrai nombre premier. Les tests du frontend,
    eux, utilisent de vraies clés Web Crypto.
    """
    modulus = bytes([0xC0 | (seed & 0x0F)]) + bytes(
        (seed * 7 + index) % 251 for index in range(255)
    )
    return {
        "kty": "RSA",
        "n": base64.urlsafe_b64encode(modulus).rstrip(b"=").decode("ascii"),
        "e": "AQAB",
        "alg": "RSA-OAEP-256",
    }


def b64(payload: bytes) -> str:
    return base64.b64encode(payload).decode("ascii")


def iv_b64() -> str:
    """IV GCM de 12 octets, taille valide sans être aléatoire."""
    return b64(bytes(range(12)))


def ciphertext_b64() -> str:
    return b64(b"0123456789abcdef" + bytes(16))


def wrapped_key_b64() -> str:
    return b64(bytes(range(256)))


def publish_public_key(client: TestClient, seed: int = 0) -> dict[str, str]:
    """Publie une clé publique synthétique et renvoie la réponse."""
    response = client.put(
        "/keys/me",
        json={"public_key_jwk": public_jwk(seed)},
        headers=csrf_headers(client),
    )
    assert response.status_code == 200, response.text
    return response.json()


def dummy_object_id() -> str:
    """Identifiant de la forme d'un ObjectId, pour un utilisateur inexistant.

    Vingt-quatre caractères hexadécimaux : c'est la longueur que MongoDB
    attend, et une chaîne UUID complète (32 caractères) serait rejetée avant
    même d'atteindre la base.
    """
    return uuid.uuid4().hex[:24]


def user_id_of(client: TestClient, username: str) -> str:
    """Identifiant interne d'un utilisateur inscrit."""
    mongo = sync_database()
    try:
        document = mongo[get_settings().mongo_db_name].users.find_one({"username": username})
    finally:
        mongo.close()
    assert document is not None, f"Utilisateur introuvable : {username}"
    return str(document["_id"])


def current_user_id(client: TestClient) -> str:
    """Identifiant de l'utilisateur auquel la session courante appartient.

    Passe par `/auth/me` plutôt que par la base : la plupart des tests ont besoin
    de « moi » parce que c'est le créateur du serveur et donc le seul habilité à
    distribuer une clé de salon. Lire l'identifiant depuis la session les dispense
    de connaître le nom sous lequel ils se sont inscrits.
    """
    response = client.get("/auth/me")
    assert response.status_code == 200, response.text
    return str(response.json()["id"])


def create_channel(
    client: TestClient,
    name: str = "general",
    server_id: str | None = None,
) -> dict[str, object]:
    """Crée un canal et renvoie sa représentation.

    Un canal naît dans un serveur, et seul le créateur de ce serveur peut en
    créer un. `server_id` omis, on crée donc un serveur au passage : l'appelant
    est alors son créateur, ce qui rend l'opération possible sans que le test ait
    à connaître la règle. Les tests qui vérifient la règle eux-mêmes passent un
    `server_id` explicite, ou refusent la route sans cet appel.

    Une clé publique est publiée avant l'appel : `POST /servers/{id}/channels`
    l'exige, puisque c'est au moment de créer le salon que son auteur aura une clé
    à emballer.
    """
    if server_id is None:
        server_id = str(create_server(client)["id"])
    publish_public_key(client)
    response = client.post(
        f"/servers/{server_id}/channels",
        json={"name": name, "client_ref": str(uuid.uuid4())},
        headers=csrf_headers(client),
    )
    assert response.status_code == 201, response.text
    return response.json()


def add_server_member(
    client: TestClient, server_id: str, user_id: str, expected_status: int = 200
) -> None:
    """Ajoute un membre à un serveur via l'API, et vérifie le statut attendu.

    N'est pas un raccourci anodin : l'adhésion a des règles qu'un test doit
    souvent éprouver — refus d'un membre ordinaire, refus d'un tiers, refus de
    l'auto-adhésion. Passer par l'API plutôt que par la base garde ces refus
    dans le périmètre du test, au lieu de les court-circuiter.

    La réponse n'est pas renvoyée : un test qui a besoin de la liste des membres
    relit le serveur par `GET /servers/{id}`, ce qui est la source de vérité de
    toute façon.
    """
    response = client.post(
        f"/servers/{server_id}/members",
        json={"user_id": user_id},
        headers=csrf_headers(client),
    )
    assert response.status_code == expected_status, response.text


def remove_server_member(
    client: TestClient, server_id: str, user_id: str, expected_status: int = 200
) -> None:
    """Retire un membre d'un serveur via l'API. Voir `add_server_member`."""
    response = client.delete(
        f"/servers/{server_id}/members/{user_id}",
        headers=csrf_headers(client),
    )
    assert response.status_code == expected_status, response.text


def create_server(client: TestClient, name: str = "general") -> dict[str, object]:
    """Crée un serveur et renvoie sa représentation.

    Aucune clé publique n'est publiée avant l'appel, contrairement à
    `create_channel` : `POST /servers` n'en exige pas. C'est volontaire, pour que
    les tests de création de serveur valident la règle réelle de la route au lieu
    d'un contournement.
    """
    response = client.post("/servers", json={"name": name}, headers=csrf_headers(client))
    assert response.status_code == 201, response.text
    return response.json()


def server_document(server_id: str) -> dict[str, object]:
    """Document Mongo brut d'un serveur, pour vérifier ce qui est réellement stocké."""
    mongo = sync_database()
    try:
        servers = mongo[get_settings().mongo_db_name].servers
        document = servers.find_one({"_id": ObjectId(server_id)})
    finally:
        mongo.close()
    assert document is not None, f"Serveur introuvable : {server_id}"
    return document
