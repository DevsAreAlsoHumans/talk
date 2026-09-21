"""Pièces jointes chiffrées (images/GIF) : ``POST /api/rooms/{id}/attachments``.

Contrat : le serveur ne manipule toujours que du chiffré (nonce + ciphertext en
base64, jamais de clair ni de clé). Une image dépassant la limite de
``POST /messages`` (ciphertext ≤ 4096) passe par cet endpoint dédié ; le message
créé porte ``kind="image"`` et un ``mime`` optionnel, apparaît dans l'historique
et est diffusé via WebSocket exactement comme un message textuel.
"""

from __future__ import annotations

from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.schemas.messages import MAX_ATTACHMENT_B64
from tests.helpers.crypto_client import (
    SyncBrowser,
    create_room,
    csrf_headers,
    encrypt_message,
    generate_room_key,
    register,
)

#: Champs du contrat v1 d'un message (inchangés : toujours présents).
_V1_FIELDS = {"id", "seq", "room_id", "author_id", "nonce", "ciphertext", "created_at"}


async def test_post_image_attachment_201_and_in_history(client, redis) -> None:
    """Une image chiffrée valide est créée (201) avec ``kind``/``mime`` et se
    retrouve dans l'historique ; Redis ne stocke que du chiffré."""
    data = await register(client, "alice_img", "password123")
    room = await create_room(client, "galerie", data["csrf_token"])
    room_key = generate_room_key()
    nonce, ciphertext = encrypt_message(room_key, "PNG-BYTES-CHIFFRES")

    response = await client.post(
        f"/api/rooms/{room['id']}/attachments",
        json={"kind": "image", "mime": "image/png", "nonce": nonce, "ciphertext": ciphertext},
        headers=csrf_headers(data["csrf_token"]),
    )
    assert response.status_code == 201, response.text
    message = response.json()["message"]
    assert message["kind"] == "image"
    assert message["mime"] == "image/png"
    assert message["room_id"] == room["id"]
    assert set(message) >= _V1_FIELDS

    # Historique : le message est présent avec son kind/mime.
    history = (await client.get(f"/api/rooms/{room['id']}/messages", params={"limit": 50})).json()[
        "messages"
    ]
    assert [item["id"] for item in history] == [message["id"]]
    assert history[0]["kind"] == "image"
    assert history[0]["mime"] == "image/png"

    # Stockage : uniquement nonce + ciphertext ; mime/kind conservés.
    stored = redis.hgetall(f"message:{message['id']}")
    assert stored["ciphertext"] == ciphertext
    assert stored["nonce"] == nonce
    assert stored["kind"] == "image"
    assert stored["mime"] == "image/png"


async def test_attachment_without_mime_is_stored_without_mime(client, redis) -> None:
    """``mime`` absent : l'image est acceptée et aucun champ ``mime`` n'est
    stocké dans le hash Redis."""
    data = await register(client, "alice_img_nomime", "password123")
    room = await create_room(client, "galerie-sans-mime", data["csrf_token"])
    nonce, ciphertext = encrypt_message(generate_room_key(), "image opaque")

    response = await client.post(
        f"/api/rooms/{room['id']}/attachments",
        json={"kind": "image", "nonce": nonce, "ciphertext": ciphertext},
        headers=csrf_headers(data["csrf_token"]),
    )
    assert response.status_code == 201, response.text
    message = response.json()["message"]
    assert message["kind"] == "image"
    assert message["mime"] is None
    assert "mime" not in redis.hgetall(f"message:{message['id']}")


async def test_text_message_stays_kind_text_and_keeps_v1_shape(client, redis) -> None:
    """Rétro-compatibilité : un message textuel v1 reste un message v1.

    Les champs v1 sont toujours présents et inchangés ; les nouveaux champs
    valent ``kind="text"`` et ``mime=None``, et rien de superflu (pas de champ
    ``mime``) n'est écrit dans Redis.
    """
    data = await register(client, "alice_txt", "password123")
    room = await create_room(client, "textuel", data["csrf_token"])
    nonce, ciphertext = encrypt_message(generate_room_key(), "bonjour")

    posted = (
        await client.post(
            f"/api/rooms/{room['id']}/messages",
            json={"nonce": nonce, "ciphertext": ciphertext},
            headers=csrf_headers(data["csrf_token"]),
        )
    ).json()["message"]

    assert set(posted) >= _V1_FIELDS
    assert posted["kind"] == "text"
    assert posted["mime"] is None
    stored = redis.hgetall(f"message:{posted['id']}")
    assert stored["kind"] == "text"
    assert "mime" not in stored

    history = (await client.get(f"/api/rooms/{room['id']}/messages", params={"limit": 50})).json()[
        "messages"
    ]
    assert set(history[0]) >= _V1_FIELDS
    assert history[0]["kind"] == "text"
    assert history[0]["mime"] is None


async def test_attachment_requires_membership(make_client, client) -> None:
    """Un non-membre du salon reçoit 403, comme pour ``POST /messages``."""
    data = await register(client, "alice_att_mb", "password123")
    room = await create_room(client, "prive-att", data["csrf_token"])
    nonce, ciphertext = encrypt_message(generate_room_key(), "image")

    async with make_client() as outsider:
        outsider_data = await register(outsider, "eve_att_mb", "password123")
        response = await outsider.post(
            f"/api/rooms/{room['id']}/attachments",
            json={"kind": "image", "nonce": nonce, "ciphertext": ciphertext},
            headers=csrf_headers(outsider_data["csrf_token"]),
        )
        assert response.status_code == 403
        assert response.json()["detail"] == "Not a member of this room"


async def test_attachment_ciphertext_over_limit_rejected(client) -> None:
    """Un ciphertext dépassant ``MAX_ATTACHMENT_B64`` est rejeté en 422."""
    data = await register(client, "alice_att_big", "password123")
    room = await create_room(client, "gros-att", data["csrf_token"])
    nonce, _ = encrypt_message(generate_room_key(), "image")

    response = await client.post(
        f"/api/rooms/{room['id']}/attachments",
        json={
            "kind": "image",
            "nonce": nonce,
            "ciphertext": "A" * (MAX_ATTACHMENT_B64 + 1),
        },
        headers=csrf_headers(data["csrf_token"]),
    )
    assert response.status_code == 422


async def test_attachment_invalid_kind_mime_or_extra_rejected(client) -> None:
    """``kind`` hors Literal, ``mime`` non-image et champ inconnu → 422."""
    data = await register(client, "alice_att_inv", "password123")
    room = await create_room(client, "invalide-att", data["csrf_token"])
    url = f"/api/rooms/{room['id']}/attachments"
    headers = csrf_headers(data["csrf_token"])
    nonce, ciphertext = encrypt_message(generate_room_key(), "image")

    bad_kind = await client.post(
        url, json={"kind": "gif", "nonce": nonce, "ciphertext": ciphertext}, headers=headers
    )
    assert bad_kind.status_code == 422

    bad_mime = await client.post(
        url,
        json={"kind": "image", "mime": "text/html", "nonce": nonce, "ciphertext": ciphertext},
        headers=headers,
    )
    assert bad_mime.status_code == 422

    extra_field = await client.post(
        url,
        json={"kind": "image", "nonce": nonce, "ciphertext": ciphertext, "width": 640},
        headers=headers,
    )
    assert extra_field.status_code == 422


def test_ws_subscriber_receives_image_new_message(app: FastAPI) -> None:
    """Un abonné reçoit ``new_message`` avec ``payload.kind == "image"`` après
    un POST /attachments (diffusion strictement identique à un message)."""
    with TestClient(app) as alice_c, TestClient(app) as bob_c:
        alice = SyncBrowser(alice_c, "alice_att_ws", "password123")
        bob = SyncBrowser(bob_c, "bob_att_ws", "password123")
        alice.register()
        bob.register()
        room = alice.create_room("salon-images")
        bob.join_room(room["id"])
        room_key = alice.room_keys[room["id"]]

        with bob_c.websocket_connect("/ws") as ws:
            ws.send_json({"type": "subscribe", "room_ids": [room["id"]]})

            nonce, ciphertext = encrypt_message(room_key, "GIF-CHIFFRE")
            response = alice_c.post(
                f"/api/rooms/{room['id']}/attachments",
                json={
                    "kind": "image",
                    "mime": "image/gif",
                    "nonce": nonce,
                    "ciphertext": ciphertext,
                },
                headers=alice._headers(),
            )
            assert response.status_code == 201, response.text

            event = ws.receive_json()
            assert event["type"] == "new_message"
            assert event["payload"]["room_id"] == room["id"]
            assert event["payload"]["kind"] == "image"
            assert event["payload"]["mime"] == "image/gif"
            assert event["payload"]["nonce"] == nonce
            assert event["payload"]["ciphertext"] == ciphertext
