"""Interopérabilité : Python déchiffre ce que produit le VRAI code du navigateur (frontend/js/crypto.js).

`tests/js/js_vectors.json` est généré par `node tests/js/generate_js_vectors.mjs` (la CI le
régénère avant de lancer les tests). L'autre sens est couvert par tests/js/crypto.test.mjs.
"""

import json
from pathlib import Path

import pytest

from app.schemas import RegisterRequest
from tests.helpers import e2e

VECTORS_FILE = Path(__file__).resolve().parents[1] / "js" / "js_vectors.json"


@pytest.fixture(scope="module")
def vectors():
    return json.loads(VECTORS_FILE.read_text(encoding="utf-8"))


def test_browser_derivation_matches_the_python_reference(vectors):
    wrap_key, auth_secret = e2e.derive_keys(vectors["password"], vectors["username"], vectors["iterations"])
    assert auth_secret == vectors["auth_secret"]
    assert len(wrap_key) == 32


def test_python_can_read_everything_the_browser_produced(vectors):
    wrap_key, _ = e2e.derive_keys(vectors["password"], vectors["username"], vectors["iterations"])
    private_key = e2e.decrypt_private_key(vectors["encrypted_private_key"], wrap_key)
    assert e2e.public_key_b64(private_key.public_key()) == vectors["public_key"]

    room_key = e2e.unwrap_room_key(vectors["wrapped_room_key"], private_key)
    assert e2e.decrypt_message(room_key, vectors["message"]) == vectors["message"]["plaintext"]
    assert e2e.decrypt_bytes(room_key, vectors["media"]) == e2e.unb64(vectors["media"]["plaintext_b64"])


def test_browser_generated_keys_pass_the_server_validation(vectors):
    """Ce que le navigateur enverra à l'inscription est bien accepté par les schémas du serveur."""
    request = RegisterRequest(
        username=vectors["username"],
        auth_secret=vectors["auth_secret"],
        public_key=vectors["public_key"],
        encrypted_private_key=vectors["encrypted_private_key"],
    )
    assert request.public_key == vectors["public_key"]
