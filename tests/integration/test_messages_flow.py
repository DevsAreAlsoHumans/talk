"""Parcours messages : E2E chiffré complet (le serveur ne voit que du
chiffré), polling ``?after=`` exclusif et contrôle d'accès membre (403).
"""

from __future__ import annotations

import uuid

from fastapi import FastAPI
from fastapi.testclient import TestClient

from tests.helpers.crypto_client import (
    SyncBrowser,
    create_room,
    csrf_headers,
    encrypt_message,
    generate_room_key,
    register,
    unwrap_key,
    wrap_key,
)


def test_end_to_end_encrypted_history_and_key_recovery(app: FastAPI) -> None:
    """Scénario complet : A crée le salon, chiffre, B joint, reçoit la clé
    enveloppée (diffusion WS ``room_key``), déchiffre l'historique et répond.
    """
    secret = f"CODESECRET-{uuid.uuid4().hex}"
    with TestClient(app) as alice_c, TestClient(app) as bob_c:
        alice = SyncBrowser(alice_c, "alice_e2e", "password123")
        bob = SyncBrowser(bob_c, "bob_e2e", "password123")
        alice.register()
        bob.register()

        # Alice crée le salon ; la clé de salon reste locale au navigateur.
        room = alice.create_room("salle-secrete")
        room_id = room["id"]
        room_key = alice.room_keys[room_id]

        # Alice publie un message chiffré (déchiffrable côté navigateur).
        message = alice.post_message(room_id, secret)
        assert alice.decrypt(room_id, message) == secret

        # Bob rejoint ; Alice enveloppe la clé de salon pour Bob.
        bob.join_room(room_id)
        wrapped_for_bob = wrap_key(bob.public_key_b64, room_key)
        with bob_c.websocket_connect("/ws") as ws:
            ws.send_json({"type": "subscribe", "room_ids": [room_id]})
            alice.post_wrapped_key(room_id, bob.user_id, wrapped_for_bob)

            event = ws.receive_json()
            assert event["type"] == "room_key"
            assert event["payload"]["room_id"] == room_id
            assert event["payload"]["target_user_id"] == bob.user_id
            assert event["payload"]["wrapped_key"] == wrapped_for_bob

            # Bob déchiffre la copie : retrouve la clé de salon d'Alice.
            recovered = unwrap_key(bob.private_key, event["payload"]["wrapped_key"])
            assert recovered == room_key
            bob.room_keys[room_id] = recovered

            # Bob lit l'historique chiffré et le déchiffre.
            history = bob.get_history(room_id, after=0)
            assert [item["seq"] for item in history] == [1]
            assert bob.decrypt(room_id, history[0]) == secret

            # Bob répond — le message chiffré circule dans l'autre sens.
            reply = "bonjour alice"
            bob.post_message(room_id, reply)

        # Alice fait un polling incrémental et déchiffre la réponse de Bob.
        delta = alice.get_history(room_id, after=1)
        assert [item["seq"] for item in delta] == [2]
        assert alice.decrypt(room_id, delta[0]) == reply
        assert alice.get_history(room_id, after=2) == []


async def test_polling_after_is_exclusive(client) -> None:
    data = await register(client, "alice_pl", "password123")
    room = await create_room(client, "polling", data["csrf_token"])
    room_key = generate_room_key()

    for _ in range(3):
        nonce, ciphertext = encrypt_message(room_key, "message de test")
        await client.post(
            f"/api/rooms/{room['id']}/messages",
            json={"nonce": nonce, "ciphertext": ciphertext},
            headers=csrf_headers(data["csrf_token"]),
        )

    history = (await client.get(f"/api/rooms/{room['id']}/messages", params={"after": 0})).json()[
        "messages"
    ]
    assert [item["seq"] for item in history] == [1, 2, 3]
    delta = (await client.get(f"/api/rooms/{room['id']}/messages", params={"after": 1})).json()[
        "messages"
    ]
    assert [item["seq"] for item in delta] == [2, 3]
    empty = (await client.get(f"/api/rooms/{room['id']}/messages", params={"after": 3})).json()[
        "messages"
    ]
    assert empty == []


async def test_message_requires_membership(make_client, client) -> None:
    data = await register(client, "alice_mb", "password123")
    room = await create_room(client, "prive", data["csrf_token"])

    async with make_client() as outsider:
        outsider_data = await register(outsider, "eve_mb", "password123")
        nonce, ciphertext = encrypt_message(generate_room_key(), "message")
        response = await outsider.post(
            f"/api/rooms/{room['id']}/messages",
            json={"nonce": nonce, "ciphertext": ciphertext},
            headers=csrf_headers(outsider_data["csrf_token"]),
        )
        assert response.status_code == 403
        assert (await outsider.get(f"/api/rooms/{room['id']}/messages")).status_code == 403
