"""Génère tests/js/python_vectors.json avec l'implémentation Python de référence.

Le test Node (tests/js/crypto.test.mjs) déchiffre ces vecteurs avec frontend/js/crypto.js :
cela prouve que le navigateur sait lire ce que produit l'autre implémentation.
Usage : python -m tests.js.generate_python_vectors
"""

import json
from pathlib import Path

from tests.helpers import e2e

OUTPUT = Path(__file__).with_name("python_vectors.json")


def main() -> None:
    username, password, plaintext = "alice", "correct horse battery staple ✓", "Bonjour depuis Python 🐍"
    room_id, sender_id = "5b3b0f0e-9d2e-4a42-8f4c-3f9f0c2a7d11", "0a6a2a53-79f0-4c41-9c6e-6a3a5f2f1b90"
    media_plaintext = bytes(range(256)) * 8  # image/message vocal fictif

    identity = e2e.Identity.create(username, password)
    room_key = e2e.generate_room_key()
    message = e2e.encrypt_message(room_key, plaintext, room_id, sender_id)
    media = e2e.encrypt_bytes(room_key, media_plaintext, room_id, sender_id)
    vectors = {
        "iterations": e2e.TEST_ITERATIONS,
        "username": username,
        "password": password,
        "auth_secret": identity.auth_secret,
        "public_key": identity.public_key,
        "encrypted_private_key": e2e.encrypt_private_key(identity.private_key, identity.wrap_key),
        "wrapped_room_key": e2e.wrap_room_key(room_key, identity.public_key),
        "message": {"room_id": room_id, "sender_id": sender_id, **message, "plaintext": plaintext},
        "media": {
            "room_id": room_id,
            "sender_id": sender_id,
            **media,
            "plaintext_b64": e2e.b64(media_plaintext),
        },
    }
    OUTPUT.write_text(json.dumps(vectors, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
