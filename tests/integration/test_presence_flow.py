"""Présence en ligne : compteur par onglet (``presence:count:{uid}``), champ
``online`` dans ``GET /api/rooms/{id}/members`` et événements ``presence``
diffusés aux abonnés WebSocket.

Rappel du contrat : le serveur est le seul émetteur d'événements — la présence
est poussée par le serveur à l'ouverture/fermeture d'une connexion WebSocket,
et l'abonné ne peut s'abonner qu'aux salons dont il est membre.
"""

from __future__ import annotations

import time

from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.repositories.rooms import PRESENCE_COUNT_PREFIX
from tests.helpers.crypto_client import SyncBrowser

#: Anti-race : les opérations WS sont traitées par le serveur dans son propre
#: thread/event loop ; on pole Redis jusqu'à l'état attendu.
_WAIT_TIMEOUT = 3.0


def _wait_for(predicate, timeout: float = _WAIT_TIMEOUT) -> bool:
    """Attend que ``predicate()`` devienne vrai (polling, borné)."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(0.01)
    return False


def _presence_key(user_id: str) -> str:
    return f"{PRESENCE_COUNT_PREFIX}{user_id}"


def _member(client: TestClient, room_id: str, user_id: str) -> dict:
    members = client.get(f"/api/rooms/{room_id}/members").json()
    return next(member for member in members if member["id"] == user_id)


def test_member_online_while_ws_connected_then_offline(app: FastAPI, redis) -> None:
    """Un membre connecté en WS est ``online`` dans /members ; il repasse
    ``offline`` après fermeture de la connexion."""
    with TestClient(app) as testclient:
        alice = SyncBrowser(testclient, "alice_pr1", "password123")
        alice.register()
        room = alice.create_room("salle-pr1")
        room_id = room["id"]

        assert _member(testclient, room_id, alice.user_id)["online"] is False

        with testclient.websocket_connect("/ws") as ws:
            ws.send_json({"type": "subscribe", "room_ids": [room_id]})
            assert redis.get(_presence_key(alice.user_id)) == "1"
            assert _member(testclient, room_id, alice.user_id)["online"] is True

        assert _wait_for(lambda: redis.get(_presence_key(alice.user_id)) is None)
        assert _member(testclient, room_id, alice.user_id)["online"] is False


def test_two_tabs_stay_online_after_one_closes(app: FastAPI, redis) -> None:
    """Deux onglets connectés : la fermeture d'un seul ne passe PAS hors ligne
    (compteur 2 → 1)."""
    with TestClient(app) as testclient:
        alice = SyncBrowser(testclient, "alice_pr2", "password123")
        alice.register()
        room = alice.create_room("salle-pr2")
        room_id = room["id"]
        key = _presence_key(alice.user_id)

        with testclient.websocket_connect("/ws"):
            assert redis.get(key) == "1"
            with testclient.websocket_connect("/ws"):
                assert redis.get(key) == "2"
                assert _member(testclient, room_id, alice.user_id)["online"] is True
            # Premier onglet fermé : toujours en ligne (count 2 → 1).
            assert _wait_for(lambda: int(redis.get(key) or 0) == 1)
            assert _member(testclient, room_id, alice.user_id)["online"] is True
        # Dernier onglet fermé : hors ligne.
        assert _wait_for(lambda: redis.get(key) is None)
        assert _member(testclient, room_id, alice.user_id)["online"] is False


def test_presence_event_broadcast_to_subscribed_member(app: FastAPI, redis) -> None:
    """L'événement ``presence`` (online puis offline) est reçu par un autre
    membre déjà abonné au salon pendant la connexion de l'utilisateur.

    Alice est aussi membre d'un salon privé dont Bob n'est pas membre : la
    diffusion reste limitée aux salons d'Alice ∩ abonnements de Bob (Bob ne
    reçoit donc exactement UN événement par bascule, pas un par salon).
    """
    with TestClient(app) as alice_c, TestClient(app) as bob_c:
        alice = SyncBrowser(alice_c, "alice_pr3", "password123")
        bob = SyncBrowser(bob_c, "bob_pr3", "password123")
        alice.register()
        bob.register()
        room = alice.create_room("salle-pr3")
        alice.create_room("prive-pr3")  # salon où Bob n'est pas membre
        bob.join_room(room["id"])

        with bob_c.websocket_connect("/ws") as bob_ws:
            bob_ws.send_json({"type": "subscribe", "room_ids": [room["id"]]})
            with alice_c.websocket_connect("/ws"):
                online = bob_ws.receive_json()
                assert online["type"] == "presence"
                assert online["payload"] == {"user_id": alice.user_id, "online": True}
                assert redis.get(_presence_key(alice.user_id)) == "1"
            # Alice s'est déconnectée : événement offline poussé à Bob.
            assert _wait_for(lambda: redis.get(_presence_key(alice.user_id)) is None)
            offline = bob_ws.receive_json()
            assert offline["type"] == "presence"
            assert offline["payload"] == {"user_id": alice.user_id, "online": False}


def test_presence_count_key_lifecycle(app: FastAPI, redis) -> None:
    """La clé ``presence:count:{uid}`` existe en Redis pendant la connexion et
    disparaît après la fermeture du WebSocket."""
    with TestClient(app) as testclient:
        alice = SyncBrowser(testclient, "alice_pr4", "password123")
        alice.register()
        key = _presence_key(alice.user_id)
        assert redis.get(key) is None

        with testclient.websocket_connect("/ws") as ws:
            assert redis.get(key) == "1"
            ws.send_json({"type": "unsubscribe", "room_ids": []})

        assert _wait_for(lambda: redis.get(key) is None)
