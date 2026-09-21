"""Édition d'un message par son auteur (contrat v2 du PATCH messages).

Couvre le contrat ``PATCH /api/rooms/{room_id}/messages/{message_id}`` :
- le corps réutilise ``MessageCreate`` (uniquement ``{nonce, ciphertext}``
  base64) : le client re-chiffre le nouveau texte avec la clé du salon, le
  serveur ne voit jamais de clair ;
- 200 pour l'auteur : ``edited: true``, nouveau ciphertext dans l'historique
  et déchiffrable avec la clé du salon ; ``created_at``/``seq`` inchangés,
  ``kind`` préservé ; le hash Redis reçoit ``edited: 1`` ;
- 403 non-auteur, 404 message inexistant ou appartenant à un autre salon ;
- 422 corps invalide (ciphertext trop long, base64 invalide, champ inconnu) ;
- diffusion WebSocket ``message_updated`` aux abonnés du salon.
"""

from __future__ import annotations

from fastapi import FastAPI
from fastapi.testclient import TestClient

from tests.helpers.crypto_client import (
    SyncBrowser,
    create_room,
    csrf_headers,
    decrypt_message,
    encrypt_message,
    generate_room_key,
    get_history,
    post_message,
    register,
)

B64 = "bm9uY2U="  # nonce base64 valide pour les corps de test
B64_C = "Y2lwaGVy"  # ciphertext base64 valide ("cipher")


async def test_author_edits_message(client, redis) -> None:
    """L'auteur remplace le contenu chiffré : 200, ``edited: true``, historique
    déchiffrable avec la clé du salon, ``created_at``/``seq``/``kind`` inchangés."""
    data = await register(client, "alice_ed", "password123")
    room = await create_room(client, "edit-salon", data["csrf_token"])
    room_key = generate_room_key()

    nonce, ciphertext = encrypt_message(room_key, "version originale")
    original = await post_message(client, room["id"], nonce, ciphertext, data["csrf_token"])

    new_nonce, new_ciphertext = encrypt_message(room_key, "version corrigée")
    response = await client.patch(
        f"/api/rooms/{room['id']}/messages/{original['id']}",
        json={"nonce": new_nonce, "ciphertext": new_ciphertext},
        headers=csrf_headers(data["csrf_token"]),
    )
    assert response.status_code == 200
    body = response.json()
    assert set(body) == {"message"}
    updated = body["message"]
    assert updated["id"] == original["id"]
    assert updated["edited"] is True
    assert updated["ciphertext"] == new_ciphertext
    assert updated["nonce"] == new_nonce
    assert updated["created_at"] == original["created_at"]
    assert updated["seq"] == original["seq"]
    assert updated["kind"] == "text"

    # Le hash Redis porte les nouvelles valeurs + le drapeau d'édition.
    stored = redis.hgetall(f"message:{original['id']}")
    assert stored["ciphertext"] == new_ciphertext
    assert stored["nonce"] == new_nonce
    assert stored["edited"] == "1"
    assert stored["created_at"] == original["created_at"]

    # L'historique reflète l'édition ; le déchiffrement (E2E) donne le nouveau texte.
    history = await get_history(client, room["id"])
    assert len(history) == 1
    assert history[0]["ciphertext"] == new_ciphertext
    assert history[0]["edited"] is True
    assert history[0]["created_at"] == original["created_at"]
    assert history[0]["seq"] == original["seq"]
    assert history[0]["kind"] == "text"
    assert decrypt_message(room_key, history[0]["nonce"], history[0]["ciphertext"]) == (
        "version corrigée"
    )


async def test_edit_by_non_author_403(make_client, client) -> None:
    """Alice ne peut pas éditer le message de Bob, même en étant membre du salon."""
    data = await register(client, "alice_na", "password123")
    room = await create_room(client, "edit-na", data["csrf_token"])
    room_key = generate_room_key()

    async with make_client() as bob:
        bob_data = await register(bob, "bob_na", "password123")
        join = await bob.post(
            f"/api/rooms/{room['id']}/join", headers=csrf_headers(bob_data["csrf_token"])
        )
        assert join.status_code == 200
        nonce, ciphertext = encrypt_message(room_key, "message de bob")
        bob_message = await post_message(bob, room["id"], nonce, ciphertext, bob_data["csrf_token"])

    response = await client.patch(
        f"/api/rooms/{room['id']}/messages/{bob_message['id']}",
        json={"nonce": nonce, "ciphertext": ciphertext},
        headers=csrf_headers(data["csrf_token"]),
    )
    assert response.status_code == 403
    assert response.json()["detail"] == "Only the author can edit this message"

    # Le contenu original est intact (aucune modification partielle).
    history = await get_history(client, room["id"])
    assert history[0]["ciphertext"] == ciphertext
    assert history[0]["edited"] is False


async def test_edit_unknown_or_foreign_message_404(make_client, client) -> None:
    """404 pour un id inconnu comme pour un message d'un AUTRE salon que l'URL.

    Dans le second cas, le contrôrôle de « salon du message » doit précéder le
    contrôle d'auteur : un ex-membre du salon B qui passe par le salon A reçoit
    un 404 générique (on ne fuite pas l'existence du message) et le message
    reste intact pour les membres restants.
    """
    data = await register(client, "alice_uf", "password123")
    room_a = await create_room(client, "edit-f-a", data["csrf_token"])
    room_b = await create_room(client, "edit-f-b", data["csrf_token"])
    room_key = generate_room_key()
    nonce, ciphertext = encrypt_message(room_key, "cible")

    # Id de message inconnu (jamais créé) → 404.
    ghost = "0" * 32
    unknown = await client.patch(
        f"/api/rooms/{room_a['id']}/messages/{ghost}",
        json={"nonce": nonce, "ciphertext": ciphertext},
        headers=csrf_headers(data["csrf_token"]),
    )
    assert unknown.status_code == 404
    assert unknown.json()["detail"] == "Message not found"

    async with make_client() as bob:
        bob_data = await register(bob, "bob_uf", "password123")
        joined = await bob.post(
            f"/api/rooms/{room_b['id']}/join", headers=csrf_headers(bob_data["csrf_token"])
        )
        assert joined.status_code == 200

        target = await post_message(client, room_b["id"], nonce, ciphertext, data["csrf_token"])

        leave = await client.post(
            f"/api/rooms/{room_b['id']}/leave", headers=csrf_headers(data["csrf_token"])
        )
        assert leave.status_code == 204

        # Alice est toujours membre de A : c'est le contrôle « salon du message »
        # qui doit rejeter la requête, en 404 (l'auteur du message serait Alice).
        exploit = await client.patch(
            f"/api/rooms/{room_a['id']}/messages/{target['id']}",
            json={"nonce": nonce, "ciphertext": ciphertext},
            headers=csrf_headers(data["csrf_token"]),
        )
        assert exploit.status_code == 404
        assert exploit.json()["detail"] == "Message not found"

        # Le message de B est intact pour Bob, membre restant.
        history = await get_history(bob, room_b["id"])
        assert [item["id"] for item in history] == [target["id"]]
        assert history[0]["ciphertext"] == ciphertext
        assert history[0]["edited"] is False


async def test_edit_invalid_body_422(client) -> None:
    """Corps invalide → 422 : ciphertext trop long, base64 invalide, extra."""
    data = await register(client, "alice_inv", "password123")
    room = await create_room(client, "edit-inv", data["csrf_token"])
    room_key = generate_room_key()
    nonce, ciphertext = encrypt_message(room_key, "cible")
    message = await post_message(client, room["id"], nonce, ciphertext, data["csrf_token"])

    url = f"/api/rooms/{room['id']}/messages/{message['id']}"
    headers = csrf_headers(data["csrf_token"])

    too_long = await client.patch(
        url, json={"nonce": B64, "ciphertext": "YQ==" * 5000}, headers=headers
    )
    assert too_long.status_code == 422

    bad_b64 = await client.patch(
        url, json={"nonce": "!!!pas-du-base64!!!", "ciphertext": "YQ=="}, headers=headers
    )
    assert bad_b64.status_code == 422

    extra_field = await client.patch(
        url, json={"nonce": B64, "ciphertext": B64_C, "kind": "text"}, headers=headers
    )
    assert extra_field.status_code == 422


def test_ws_message_updated(app: FastAPI) -> None:
    """Un abonné du salon reçoit ``message_updated`` (payload ``edited: true``)."""
    with TestClient(app) as alice_c, TestClient(app) as bob_c:
        alice = SyncBrowser(alice_c, "alice_wed", "password123")
        bob = SyncBrowser(bob_c, "bob_wed", "password123")
        alice.register()
        bob.register()

        room = alice.create_room("salon-edit")
        bob.join_room(room["id"])
        message = alice.post_message(room["id"], "version 1")

        with bob_c.websocket_connect("/ws") as ws:
            ws.send_json({"type": "subscribe", "room_ids": [room["id"]]})

            new_nonce, new_ciphertext = encrypt_message(alice.room_keys[room["id"]], "version 2")
            response = alice_c.patch(
                f"/api/rooms/{room['id']}/messages/{message['id']}",
                json={"nonce": new_nonce, "ciphertext": new_ciphertext},
                headers=alice._headers(),
            )
            assert response.status_code == 200

            event = ws.receive_json()
            assert event["type"] == "message_updated"
            payload = event["payload"]
            assert payload["id"] == message["id"]
            assert payload["edited"] is True
            assert payload["ciphertext"] == new_ciphertext
            # E2E : le destinataire déchiffre la version éditée avec la clé du salon.
            assert alice.decrypt(room["id"], payload) == "version 2"
