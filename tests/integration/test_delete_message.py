"""Suppression d'un message (auteur uniquement).

Couvre le contrat v2 du DELETE ``/api/rooms/{room_id}/messages/{message_id}`` :
- 204 pour l'auteur, message invisible ensuite, hash Redis purgé ;
- les ``seq`` sont conservés (trou de numérotation : suppression du 3, le
  suivant a seq=4) ;
- 403 non-auteur / non-membre, 404 message inexistant ;
- le message doit appartenir au salon de l'URL (un ex-membre qui passe un
  autre salon obtient un 404 : le message reste intact dans son salon) ;
- diffusion WebSocket ``message_deleted`` aux abonnés du salon.
"""

from __future__ import annotations

from fastapi import FastAPI
from fastapi.testclient import TestClient

from tests.helpers.crypto_client import (
    SyncBrowser,
    create_room,
    csrf_headers,
    encrypt_message,
    generate_room_key,
    get_history,
    post_message,
    register,
)


async def test_author_deletes_own_message_and_seq_gap(client, redis) -> None:
    """L'auteur supprime son message : 204, disparition de l'historique et du
    hash Redis, et les ``seq`` suivants ne sont pas renumérotés (trou voulu)."""
    data = await register(client, "alice_del", "password123")
    room = await create_room(client, "del-salon", data["csrf_token"])
    room_key = generate_room_key()

    for seq in (1, 2, 3):
        nonce, ciphertext = encrypt_message(room_key, f"message {seq}")
        posted = await post_message(client, room["id"], nonce, ciphertext, data["csrf_token"])
        assert posted["seq"] == seq
    deleted = posted

    response = await client.delete(
        f"/api/rooms/{room['id']}/messages/{deleted['id']}",
        headers=csrf_headers(data["csrf_token"]),
    )
    assert response.status_code == 204

    # Le message ne réapparaît plus dans l'historique et le hash est purgé.
    history = await get_history(client, room["id"])
    assert [item["seq"] for item in history] == [1, 2]
    assert redis.hgetall(f"message:{deleted['id']}") == {}

    # Le trou de seq est conservé : le message suivant porte bien seq=4.
    nonce, ciphertext = encrypt_message(room_key, "message 4")
    next_message = await post_message(client, room["id"], nonce, ciphertext, data["csrf_token"])
    assert next_message["seq"] == 4
    history = await get_history(client, room["id"])
    assert [item["seq"] for item in history] == [1, 2, 4]


async def test_only_author_can_delete_member_message(make_client, client) -> None:
    """Alice ne peut pas supprimer le message de Bob, même en étant membre."""
    data = await register(client, "alice_own", "password123")
    room = await create_room(client, "own-salon", data["csrf_token"])

    async with make_client() as bob:
        bob_data = await register(bob, "bob_own", "password123")
        join = await bob.post(
            f"/api/rooms/{room['id']}/join", headers=csrf_headers(bob_data["csrf_token"])
        )
        assert join.status_code == 200
        nonce, ciphertext = encrypt_message(generate_room_key(), "message de bob")
        bob_message = await post_message(bob, room["id"], nonce, ciphertext, bob_data["csrf_token"])

    response = await client.delete(
        f"/api/rooms/{room['id']}/messages/{bob_message['id']}",
        headers=csrf_headers(data["csrf_token"]),
    )
    assert response.status_code == 403
    assert response.json()["detail"] == "Only the author can delete this message"


async def test_delete_non_member_403_and_missing_message_404(make_client, client) -> None:
    """Un non-membre est refusé (403) ; un message inexistant renvoie 404."""
    data = await register(client, "alice_nm", "password123")
    room = await create_room(client, "nm-salon", data["csrf_token"])
    nonce, ciphertext = encrypt_message(generate_room_key(), "message")
    message = await post_message(client, room["id"], nonce, ciphertext, data["csrf_token"])

    async with make_client() as outsider:
        outsider_data = await register(outsider, "eve_nm", "password123")
        response = await outsider.delete(
            f"/api/rooms/{room['id']}/messages/{message['id']}",
            headers=csrf_headers(outsider_data["csrf_token"]),
        )
        assert response.status_code == 403
        assert response.json()["detail"] == "Not a member of this room"

    # Membre du salon, mais id de message inconnu (jamais créé).
    ghost = "0" * 32
    response = await client.delete(
        f"/api/rooms/{room['id']}/messages/{ghost}",
        headers=csrf_headers(data["csrf_token"]),
    )
    assert response.status_code == 404
    assert response.json()["detail"] == "Message not found"


async def test_cannot_delete_message_of_left_room_via_another_room(make_client, client) -> None:
    """P1 — un ex-membre d'un salon B ne supprime pas ses messages via le salon A.

    Alice crée A et B, poste un message dans B puis quitte B (elle reste
    membre de A) : ``DELETE /api/rooms/{A}/messages/{idDuMessageDeB}`` doit
    renvoyer 404 (le message n'appartient pas au salon de l'URL) et le
    message doit rester intact dans B pour un membre restant (Bob).
    """
    data = await register(client, "alice_xroom", "password123")
    room_a = await create_room(client, "salon-A", data["csrf_token"])
    room_b = await create_room(client, "salon-B", data["csrf_token"])
    room_key = generate_room_key()

    async with make_client() as bob:
        bob_data = await register(bob, "bob_xroom", "password123")
        joined = await bob.post(
            f"/api/rooms/{room_b['id']}/join", headers=csrf_headers(bob_data["csrf_token"])
        )
        assert joined.status_code == 200

        nonce, ciphertext = encrypt_message(room_key, "message cible de B")
        target = await post_message(client, room_b["id"], nonce, ciphertext, data["csrf_token"])

        leave = await client.post(
            f"/api/rooms/{room_b['id']}/leave", headers=csrf_headers(data["csrf_token"])
        )
        assert leave.status_code == 204

        # Alice est toujours membre de A : c'est le contrôle de « salon du
        # message » qui doit rejeter la requête, en 404 (sans fuiter l'existence).
        exploit = await client.delete(
            f"/api/rooms/{room_a['id']}/messages/{target['id']}",
            headers=csrf_headers(data["csrf_token"]),
        )
        assert exploit.status_code == 404
        assert exploit.json()["detail"] == "Message not found"

        # Le message de B est intact pour Bob, membre restant.
        history = await get_history(bob, room_b["id"])
        assert [item["id"] for item in history] == [target["id"]]


def test_ws_message_deleted_event_broadcast(app: FastAPI) -> None:
    """Un abonné du salon reçoit bien l'événement ``message_deleted``."""
    with TestClient(app) as alice_c, TestClient(app) as bob_c:
        alice = SyncBrowser(alice_c, "alice_wsdel", "password123")
        bob = SyncBrowser(bob_c, "bob_wsdel", "password123")
        alice.register()
        bob.register()

        room = alice.create_room("salon-del")
        bob.join_room(room["id"])
        message = alice.post_message(room["id"], "à supprimer")

        with bob_c.websocket_connect("/ws") as ws:
            ws.send_json({"type": "subscribe", "room_ids": [room["id"]]})

            response = alice_c.delete(
                f"/api/rooms/{room['id']}/messages/{message['id']}",
                headers=alice._headers(),
            )
            assert response.status_code == 204

            event = ws.receive_json()
            assert event["type"] == "message_deleted"
            assert event["payload"]["room_id"] == room["id"]
            assert event["payload"]["id"] == message["id"]
            assert event["payload"]["seq"] == message["seq"]
