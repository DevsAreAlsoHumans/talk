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
    """Client synchrone : suffisant pour nettoyer et inspecter la base."""
    return MongoClient(get_settings().mongo_url, serverSelectionTimeoutMS=10000)


def purge_database() -> None:
    mongo = sync_database()
    try:
        database = mongo[get_settings().mongo_db_name]
        database.sessions.delete_many({})
        database.users.delete_many({})
        database.channels.delete_many({})
        database.channel_keys.delete_many({})
        database.messages.delete_many({})
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


def create_channel(client: TestClient, name: str = "general") -> dict[str, object]:
    """Crée un canal et renvoie sa représentation."""
    publish_public_key(client)
    response = client.post(
        "/channels",
        json={"name": name, "client_ref": str(uuid.uuid4())},
        headers=csrf_headers(client),
    )
    assert response.status_code == 201, response.text
    return response.json()
