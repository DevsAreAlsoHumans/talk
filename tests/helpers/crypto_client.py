"""« Navigateur » de référence : reproduit exactement le contrat E2E du frontend.

Cryptographie imposée par le contrat d'intégration (PLAN.md §3) :
- clés publiques : RSA-OAEP-256, encodées **SPKI base64** (SubjectPublicKeyInfo) ;
- clé de salon : 32 octets aléatoires ; copie enveloppée = RSA-OAEP-256 puis base64 ;
- messages : AES-256-GCM, **nonce unique de 12 octets**, corps
  ``{nonce: b64, ciphertext: b64}`` (le tag AEAD est inclus dans le ciphertext).

Ce module fournit les primitives pures (wrap/unwrap/encrypt/decrypt), des
helpers HTTP asynchrones pour ``httpx.AsyncClient`` (REST) et la classe
``SyncBrowser`` pour ``fastapi.testclient.TestClient`` (REST + WebSocket,
httpx ne gérant pas WebSocket).
"""

from __future__ import annotations

import base64
import os
from typing import TYPE_CHECKING

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

if TYPE_CHECKING:
    from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey

#: Origine envoyée par le « navigateur » (correspond à base_url des clients de test).
ORIGIN = "http://testserver"

# ---------------------------------------------------------------------------
# Primitives cryptographiques (référence Python du code WebCrypto du frontend)
# ---------------------------------------------------------------------------


def generate_user_keypair() -> tuple[RSAPrivateKey, str]:
    """Génère une paire RSA-2048 → ``(clé privée, clé publique SPKI base64)``."""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    der = private_key.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return private_key, base64.b64encode(der).decode("ascii")


def generate_room_key() -> bytes:
    """Clé de salon symétrique (32 octets ⇒ AES-256-GCM)."""
    return os.urandom(32)


def wrap_key(public_key_b64: str, room_key: bytes) -> str:
    """Enveloppe (chiffre) la clé de salon pour un possesseur de la clé publique SPKI."""
    der = base64.b64decode(public_key_b64, validate=True)
    public_key = serialization.load_der_public_key(der)
    wrapped = public_key.encrypt(
        room_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    return base64.b64encode(wrapped).decode("ascii")


def unwrap_key(private_key: RSAPrivateKey, wrapped_b64: str) -> bytes:
    """Dé-enveloppe une clé de salon avec la clé privée RSA du destinataire."""
    wrapped = base64.b64decode(wrapped_b64, validate=True)
    return private_key.decrypt(
        wrapped,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )


def encrypt_message(room_key: bytes, plaintext: str) -> tuple[str, str]:
    """Chiffre un texte clair → ``(nonce_b64, ciphertext_b64)`` (AES-256-GCM)."""
    nonce = os.urandom(12)
    ciphertext = AESGCM(room_key).encrypt(nonce, plaintext.encode("utf-8"), None)
    return base64.b64encode(nonce).decode("ascii"), base64.b64encode(ciphertext).decode("ascii")


def decrypt_message(room_key: bytes, nonce_b64: str, ciphertext_b64: str) -> str:
    """Déchiffre un message (la vérification AEAD échoue si les clés diffèrent)."""
    nonce = base64.b64decode(nonce_b64, validate=True)
    ciphertext = base64.b64decode(ciphertext_b64, validate=True)
    return AESGCM(room_key).decrypt(nonce, ciphertext, None).decode("utf-8")


def default_public_key() -> str:
    """Clé publique SPKI RSA-2048 de référence (une seule génération à l'import)."""
    return _DEFAULT_PUBLIC_KEY


def _build_default_public_key() -> str:
    return generate_user_keypair()[1]


_DEFAULT_PUBLIC_KEY: str = _build_default_public_key()

# ---------------------------------------------------------------------------
# Helpers REST asynchrones (httpx.AsyncClient)
# ---------------------------------------------------------------------------


def csrf_headers(csrf_token: str) -> dict[str, str]:
    """Headers d'une mutation : token CSRF + Origin (nécessaire au middleware)."""
    return {"x-csrf-token": csrf_token, "origin": ORIGIN}


async def fetch_csrf(client) -> str:
    """GET /api/csrf → token CSRF de la session (le cookie est géré par le client)."""
    response = await client.get("/api/csrf")
    assert response.status_code == 200, response.text
    return response.json()["csrf_token"]


async def register(client, username: str, password: str, *, public_key: str | None = None) -> dict:
    """Inscription complète (GET /api/csrf puis POST) → réponse 201 JSON."""
    csrf_token = await fetch_csrf(client)
    key = public_key or default_public_key()
    response = await client.post(
        "/api/auth/register",
        json={"username": username, "password": password, "public_key": key},
        headers=csrf_headers(csrf_token),
    )
    assert response.status_code == 201, response.text
    return response.json()


async def login(client, username: str, password: str) -> dict:
    """Connexion complète → réponse 200 JSON."""
    csrf_token = await fetch_csrf(client)
    response = await client.post(
        "/api/auth/login",
        json={"username": username, "password": password},
        headers=csrf_headers(csrf_token),
    )
    assert response.status_code == 200, response.text
    return response.json()


async def create_room(client, name: str, csrf_token: str) -> dict:
    """POST /api/rooms → salon créé (201)."""
    response = await client.post(
        "/api/rooms", json={"name": name}, headers=csrf_headers(csrf_token)
    )
    assert response.status_code == 201, response.text
    return response.json()


async def post_message(client, room_id: str, nonce: str, ciphertext: str, csrf_token: str) -> dict:
    """POST /api/rooms/{id}/messages → message créé (201)."""
    response = await client.post(
        f"/api/rooms/{room_id}/messages",
        json={"nonce": nonce, "ciphertext": ciphertext},
        headers=csrf_headers(csrf_token),
    )
    assert response.status_code == 201, response.text
    return response.json()["message"]


async def get_history(client, room_id: str, after: int = 0) -> list[dict]:
    """GET /api/rooms/{id}/messages?after= → liste des messages chiffrés."""
    response = await client.get(f"/api/rooms/{room_id}/messages", params={"after": after})
    assert response.status_code == 200, response.text
    return response.json()["messages"]


# ---------------------------------------------------------------------------
# Navigateur synchrone (TestClient : REST + WebSocket)
# ---------------------------------------------------------------------------


class SyncBrowser:
    """« Navigateur » de référence fondé sur TestClient (REST + WS).

    Un navigateur possède sa paire RSA et mémorise la clé de salon de chaque
    salon qu'il crée. Côté serveur, seul du chiffré transite ; toute la
    cryptographie a lieu « dans le navigateur ».
    """

    def __init__(self, client, username: str, password: str) -> None:
        self.client = client
        self.username = username
        self.password = password
        self.private_key, self.public_key_b64 = generate_user_keypair()
        self.room_keys: dict[str, bytes] = {}
        self.csrf_token: str | None = None
        self.user_id: str | None = None
        self.user: dict | None = None

    # ---- session / auth ----------------------------------------------------

    def fetch_csrf(self) -> str:
        response = self.client.get("/api/csrf")
        assert response.status_code == 200, response.text
        return response.json()["csrf_token"]

    def _headers(self) -> dict[str, str]:
        assert self.csrf_token is not None, "navigateur non authentifié"
        return {"x-csrf-token": self.csrf_token, "origin": ORIGIN}

    def register(self) -> dict:
        """Inscription : pose la session + token CSRF du navigateur."""
        csrf_token = self.fetch_csrf()
        response = self.client.post(
            "/api/auth/register",
            json={
                "username": self.username,
                "password": self.password,
                "public_key": self.public_key_b64,
            },
            headers={"x-csrf-token": csrf_token, "origin": ORIGIN},
        )
        assert response.status_code == 201, response.text
        data = response.json()
        self.user = data["user"]
        self.user_id = self.user["id"]
        self.csrf_token = data["csrf_token"]
        return data

    # ---- salons -------------------------------------------------------------

    def create_room(self, name: str) -> dict:
        """Crée un salon, génère la clé de salon et l'enveloppe pour soi-même."""
        response = self.client.post("/api/rooms", json={"name": name}, headers=self._headers())
        assert response.status_code == 201, response.text
        room = response.json()
        room_key = generate_room_key()
        wrapped = wrap_key(self.public_key_b64, room_key)
        key_response = self.client.post(
            f"/api/rooms/{room['id']}/keys",
            json={"target_user_id": self.user_id, "wrapped_key": wrapped},
            headers=self._headers(),
        )
        assert key_response.status_code == 201, key_response.text
        self.room_keys[room["id"]] = room_key
        return room

    def join_room(self, room_id: str) -> dict:
        response = self.client.post(f"/api/rooms/{room_id}/join", headers=self._headers())
        assert response.status_code == 200, response.text
        return response.json()

    def post_wrapped_key(self, room_id: str, target_user_id: str, wrapped_key: str) -> dict:
        """Enregistre la copie enveloppée de la clé de salon pour un membre."""
        response = self.client.post(
            f"/api/rooms/{room_id}/keys",
            json={"target_user_id": target_user_id, "wrapped_key": wrapped_key},
            headers=self._headers(),
        )
        assert response.status_code == 201, response.text
        return response.json()

    # ---- messages -----------------------------------------------------------

    def post_message(self, room_id: str, plaintext: str) -> dict:
        """Chiffre (AES-GCM) et publie un message ; renvoie la version serveur."""
        room_key = self.room_keys[room_id]
        nonce, ciphertext = encrypt_message(room_key, plaintext)
        response = self.client.post(
            f"/api/rooms/{room_id}/messages",
            json={"nonce": nonce, "ciphertext": ciphertext},
            headers=self._headers(),
        )
        assert response.status_code == 201, response.text
        return response.json()["message"]

    def get_history(self, room_id: str, after: int = 0) -> list[dict]:
        response = self.client.get(f"/api/rooms/{room_id}/messages", params={"after": after})
        assert response.status_code == 200, response.text
        return response.json()["messages"]

    def decrypt(self, room_id: str, message: dict) -> str:
        """Déchiffre un message avec la clé de salon connue du navigateur."""
        room_key = self.room_keys[room_id]
        return decrypt_message(room_key, message["nonce"], message["ciphertext"])
