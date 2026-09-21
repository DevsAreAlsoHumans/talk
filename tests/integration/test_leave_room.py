"""Quitter un salon (``POST /api/rooms/{id}/leave``) : retrait du membre et de
sa clé enveloppée, diffusion ``member_left`` aux abonnés restants et
suppression complète du salon quand le dernier membre part.
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
    register,
)

B64 = "Y2xhcw=="  # base64 valide ("claw") pour les corps de test


async def test_leave_room_removes_member_and_wrapped_key(client, make_client, redis) -> None:
    """Alice quitte un salon cohabité avec Bob : Bob ne la voit plus dans
    /members, la clé enveloppée d'Alice est supprimée et le salon disparaît
    des salons listés dans /api/me."""
    data = await register(client, "alice_lv1", "password123")
    room = await create_room(client, "salle-lv1", data["csrf_token"])
    room_id = room["id"]

    # Alice enveloppe la clé de salon pour elle-même (copie à retirer au leave).
    stored = await client.post(
        f"/api/rooms/{room_id}/keys",
        json={"target_user_id": data["user"]["id"], "wrapped_key": B64},
        headers=csrf_headers(data["csrf_token"]),
    )
    assert stored.status_code == 201

    async with make_client() as bob:
        bob_data = await register(bob, "bob_lv1", "password123")
        joined = await bob.post(
            f"/api/rooms/{room_id}/join", headers=csrf_headers(bob_data["csrf_token"])
        )
        assert joined.status_code == 200

        leave = await client.post(
            f"/api/rooms/{room_id}/leave", headers=csrf_headers(data["csrf_token"])
        )
        assert leave.status_code == 204

        # Bob ne voit plus Alice parmi les membres.
        members = (await bob.get(f"/api/rooms/{room_id}/members")).json()
        assert [member["username"] for member in members] == ["bob_lv1"]

        # La copie enveloppée d'Alice a été retirée du hash des clés.
        assert redis.hgetall(f"room:{room_id}:keys") == {}

    # Alice ne liste plus le salon dans /api/me.
    me = (await client.get("/api/me")).json()
    assert all(item["id"] != room_id for item in me["rooms"])


def test_member_left_event_broadcast_to_subscribed_member(app: FastAPI) -> None:
    """L'événement ``member_left`` est reçu par un membre restant abonné au
    salon."""
    with TestClient(app) as alice_c, TestClient(app) as bob_c:
        alice = SyncBrowser(alice_c, "alice_lv2", "password123")
        bob = SyncBrowser(bob_c, "bob_lv2", "password123")
        alice.register()
        bob.register()
        room = alice.create_room("salle-lv2")
        room_id = room["id"]
        bob.join_room(room_id)

        with bob_c.websocket_connect("/ws") as ws:
            ws.send_json({"type": "subscribe", "room_ids": [room_id]})
            response = alice_c.post(f"/api/rooms/{room_id}/leave", headers=alice._headers())
            assert response.status_code == 204

            event = ws.receive_json()
            assert event["type"] == "member_left"
            assert event["payload"]["room_id"] == room_id
            assert event["payload"]["member"] == {
                "id": alice.user_id,
                "username": "alice_lv2",
            }


async def test_last_member_leaving_deletes_room(client, redis) -> None:
    """Le dernier membre qui quitte : le salon et ses messages disparaissent."""
    data = await register(client, "alice_lv3", "password123")
    room = await create_room(client, "salle-lv3", data["csrf_token"])
    room_id = room["id"]

    nonce, ciphertext = encrypt_message(generate_room_key(), "dernier message")
    posted = await client.post(
        f"/api/rooms/{room_id}/messages",
        json={"nonce": nonce, "ciphertext": ciphertext},
        headers=csrf_headers(data["csrf_token"]),
    )
    assert posted.status_code == 201
    message_ids = redis.zrange(f"room:{room_id}:messages", 0, -1)
    assert message_ids  # le salon contient bien un message

    leave = await client.post(
        f"/api/rooms/{room_id}/leave", headers=csrf_headers(data["csrf_token"])
    )
    assert leave.status_code == 204

    assert redis.exists(f"room:{room_id}") == 0
    assert redis.exists(f"room:{room_id}:members") == 0
    assert redis.exists(f"room:{room_id}:keys") == 0
    assert redis.exists(f"room:{room_id}:messages") == 0
    assert all(redis.exists(f"message:{message_id}") == 0 for message_id in message_ids)
    assert (await client.get(f"/api/rooms/{room_id}/members")).status_code == 404


async def test_non_member_cannot_leave(make_client, client) -> None:
    """Un non-membre qui tente de quitter le salon reçoit une 403."""
    data = await register(client, "alice_lv4", "password123")
    room = await create_room(client, "prive-lv4", data["csrf_token"])

    async with make_client() as eve:
        eve_data = await register(eve, "eve_lv4", "password123")
        response = await eve.post(
            f"/api/rooms/{room['id']}/leave", headers=csrf_headers(eve_data["csrf_token"])
        )
        assert response.status_code == 403


async def test_leave_unknown_room_returns_404(client) -> None:
    """Quitter un salon inconnu → 404 (get_room_or_404, avant require_member)."""
    data = await register(client, "alice_lv5", "password123")
    response = await client.post(
        "/api/rooms/inconnue/leave", headers=csrf_headers(data["csrf_token"])
    )
    assert response.status_code == 404
