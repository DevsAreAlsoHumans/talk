"""Tests WebSocket : rejet de connexions non authentifiées / d'origine
étrangère, abonnement et réception de ``new_message`` / ``member_joined``,
diffusion de ``room_key`` après POST keys, désabonnement (route + hub).
"""

from __future__ import annotations

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

from tests.helpers.crypto_client import SyncBrowser, unwrap_key, wrap_key


def test_ws_unauthenticated_closed_4401(testclient) -> None:
    with pytest.raises(WebSocketDisconnect) as excinfo, testclient.websocket_connect("/ws"):
        pass
    assert excinfo.value.code == 4401


def test_ws_foreign_origin_closed_1008(app: FastAPI) -> None:
    with TestClient(app) as client:
        browser = SyncBrowser(client, "alice_wo", "password123")
        browser.register()
        with (
            pytest.raises(WebSocketDisconnect) as excinfo,
            client.websocket_connect("/ws", headers={"origin": "https://evil.example"}),
        ):
            pass
        assert excinfo.value.code == 1008


def test_ws_subscribed_member_receives_new_message(app: FastAPI) -> None:
    with TestClient(app) as alice_c, TestClient(app) as bob_c:
        alice = SyncBrowser(alice_c, "alice_wn", "password123")
        bob = SyncBrowser(bob_c, "bob_wn", "password123")
        alice.register()
        bob.register()
        room = alice.create_room("salle")
        bob.join_room(room["id"])

        with bob_c.websocket_connect("/ws") as ws:
            ws.send_json({"type": "subscribe", "room_ids": [room["id"]]})
            message = alice.post_message(room["id"], "coucou bob")
            event = ws.receive_json()
            assert event["type"] == "new_message"
            assert event["payload"]["room_id"] == room["id"]
            assert event["payload"]["seq"] == 1
            assert event["payload"]["ciphertext"] == message["ciphertext"]


def test_ws_room_key_broadcast_after_post_keys(app: FastAPI) -> None:
    with TestClient(app) as alice_c, TestClient(app) as bob_c:
        alice = SyncBrowser(alice_c, "alice_wk", "password123")
        bob = SyncBrowser(bob_c, "bob_wk", "password123")
        alice.register()
        bob.register()
        room = alice.create_room("cles")
        bob.join_room(room["id"])

        wrapped = wrap_key(bob.public_key_b64, alice.room_keys[room["id"]])
        with bob_c.websocket_connect("/ws") as ws:
            ws.send_json({"type": "subscribe", "room_ids": [room["id"]]})
            alice.post_wrapped_key(room["id"], bob.user_id, wrapped)

            event = ws.receive_json()
            assert event["type"] == "room_key"
            assert event["payload"]["room_id"] == room["id"]
            assert event["payload"]["target_user_id"] == bob.user_id
            assert event["payload"]["wrapped_key"] == wrapped
            assert unwrap_key(bob.private_key, wrapped) == alice.room_keys[room["id"]]


def test_ws_member_joined_broadcast(app: FastAPI) -> None:
    with TestClient(app) as alice_c, TestClient(app) as bob_c:
        alice = SyncBrowser(alice_c, "alice_wj", "password123")
        alice.register()
        room = alice.create_room("salle-join")

        with alice_c.websocket_connect("/ws") as ws:
            ws.send_json({"type": "subscribe", "room_ids": [room["id"]]})
            bob = SyncBrowser(bob_c, "bob_wj", "password123")
            bob.register()
            bob.join_room(room["id"])

            event = ws.receive_json()
            assert event["type"] == "member_joined"
            assert event["payload"]["member"]["username"] == "bob_wj"


def test_ws_unsubscribe_removes_socket_from_hub(app: FastAPI) -> None:
    with TestClient(app) as client:
        alice = SyncBrowser(client, "alice_wu", "password123")
        alice.register()
        room = alice.create_room("salle-unsub")
        hub = app.state.hub

        with client.websocket_connect("/ws") as ws:
            ws.send_json({"type": "subscribe", "room_ids": [room["id"]]})
            # Forcer un aller-retour : on reçoit un événement (abonnement actif).
            alice.post_message(room["id"], "avant désabonnement")
            event = ws.receive_json()
            assert event["type"] == "new_message"

            # On se désabonne puis on se ré-abonne à un salon factice ; le
            # relais reçu garantit que le serveur a bien traité les messages.
            ws.send_json({"type": "unsubscribe", "room_ids": [room["id"]]})
            ws.send_json({"type": "subscribe", "room_ids": ["salle-ping"]})
            ws.send_json(
                {"type": "new_message", "payload": {"room_id": "salle-ping", "seq": 1, "id": "x"}}
            )
            event = ws.receive_json()
            assert event["payload"]["room_id"] == "salle-ping"

            assert len(hub._rooms.get(room["id"], ())) == 0
            assert len(hub._rooms.get("salle-ping", ())) == 1


def test_ws_relays_new_message_events(app: FastAPI) -> None:
    with TestClient(app) as client:
        alice = SyncBrowser(client, "alice_wr", "password123")
        alice.register()
        room = alice.create_room("salle-relais")

        with client.websocket_connect("/ws") as ws:
            ws.send_json({"type": "subscribe", "room_ids": [room["id"]]})
            ws.send_json(
                {"type": "new_message", "payload": {"room_id": room["id"], "id": "abc", "seq": 99}}
            )
            event = ws.receive_json()
            assert event["type"] == "new_message"
            assert event["payload"]["seq"] == 99


async def test_hub_unsubscribe_stops_delivery(app: FastAPI) -> None:
    """Niveau hub : un socket désabonné ne reçoit plus les publications."""
    hub = app.state.hub

    class _FakeSocket:
        def __init__(self) -> None:
            self.events: list[dict] = []

        async def send_json(self, event: dict) -> None:
            self.events.append(event)

    first = _FakeSocket()
    second = _FakeSocket()
    hub.subscribe("salle", first)
    hub.subscribe("salle", second)

    await hub.publish("salle", {"type": "new_message", "payload": {"seq": 1}})
    assert len(first.events) == 1
    assert len(second.events) == 1

    hub.unsubscribe("salle", second)
    await hub.publish("salle", {"type": "new_message", "payload": {"seq": 2}})
    assert len(first.events) == 2
    assert len(second.events) == 1  # désabonné : aucun nouvel événement
