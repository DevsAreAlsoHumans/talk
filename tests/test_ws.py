"""Tests WebSocket : auth par session, appartenance au salon, broadcast E2EE.

Les payloads sont des blobs opaques dans une enveloppe {channel, payload} :
le serveur ne les interprète JAMAIS.
"""

import json

import pytest
from starlette.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

from app.realtime import ConnectionManager


def _connect(client: TestClient, room_id: str, *, origin: str | None = None):
    kwargs: dict = {"headers": {"Origin": origin}} if origin is not None else {}
    return client.websocket_connect(f"/api/ws?room_id={room_id}", **kwargs)


def _channel_id(client: TestClient, room_id: str) -> str:
    r = client.get(f"/api/rooms/{room_id}/channels")
    assert r.status_code == 200
    return r.json()[0]["id"]  # `general` créé automatiquement


def test_ws_requires_session(anonymous: TestClient) -> None:
    """Aucun cookie de session -> handshake refusé (4401)."""
    with pytest.raises(WebSocketDisconnect) as exc:
        with _connect(anonymous, "n'importe-quelle-salle"):
            pass
    assert exc.value.code == 4401


def test_ws_rejects_non_member(client: TestClient, anonymous: TestClient) -> None:
    """Authentifié mais non membre -> refusé (pas de fuite d'existence)."""
    from conftest import create_room, register

    register(client, "owner")
    room_id = create_room(client)  # salon dont "owner" est membre

    register(anonymous, "intruder")  # session valide, mais ABSENTE du salon
    with pytest.raises(WebSocketDisconnect) as exc:
        with _connect(anonymous, room_id):
            pass
    assert exc.value.code == 4401


def test_ws_relays_opaque_blob(two_members) -> None:
    alice, bob, room_id = two_members
    cid = _channel_id(alice, room_id)

    with _connect(alice, room_id) as a_ws:
        with _connect(bob, room_id) as b_ws:
            # La présence de Bob est annoncée à Alice (jamais à Bob lui-même).
            presence = a_ws.receive_json()
            assert presence["type"] == "presence" and presence["event"] == "join"

            # Alice envoie un blob chiffré : Bob reçoit exactement ce blob.
            blob = "bmUgcGFzIGRlIGNsYWlyIGRhdmFudCBsZSBzZXJ2ZXVy..."
            a_ws.send_text(json.dumps({"channel": cid, "payload": blob}))
            msg = b_ws.receive_json()

            assert msg["room_id"] == room_id
            assert msg["channel_id"] == cid
            assert msg["from"] == "alice"
            assert msg["payload"] == blob


def test_ws_accepts_same_origin_handshake(two_members) -> None:
    """Handshake depuis la même origine (le chat lui-même) : accepté."""
    alice, bob, room_id = two_members
    with _connect(alice, room_id, origin="http://testserver") as a_ws:
        with _connect(bob, room_id) as _b_ws:
            # Alice seule ne reçoit aucune frame ; l'arrivée de Bob déclenche
            # la présence et prouve que le handshake a abouti.
            assert a_ws.receive_json()["type"] == "presence"


def test_ws_rejects_third_party_origin(two_members) -> None:
    """Site tiers -> handshake refusé (anti cross-site websocket hijacking)."""
    alice, _, room_id = two_members
    with pytest.raises(WebSocketDisconnect) as exc:
        with _connect(alice, room_id, origin="https://evil.example"):
            pass
    assert exc.value.code == 1008


def test_ws_rejects_non_http_scheme_origin(two_members) -> None:
    alice, _, room_id = two_members
    with pytest.raises(WebSocketDisconnect) as exc:
        with _connect(alice, room_id, origin="ftp://localhost"):
            pass
    assert exc.value.code == 1008


def test_ws_does_not_echo_sender(two_members) -> None:
    alice, bob, room_id = two_members
    cid = _channel_id(alice, room_id)

    with _connect(alice, room_id) as a_ws:
        with _connect(bob, room_id) as b_ws:
            assert a_ws.receive_json()["type"] == "presence"

            a_ws.send_text(json.dumps({"channel": cid, "payload": "blob-a"}))
            assert b_ws.receive_json()["from"] == "alice"
            # L'émetteur ne reçoit pas sa propre frame (rendu local côté client).
            b_ws.send_text(json.dumps({"channel": cid, "payload": "blob-b"}))
            assert a_ws.receive_json()["from"] == "bob"


class FakeSocket:
    """Stub WebSocket : teste ConnectionManager sans réseau."""

    def __init__(self) -> None:
        self.sent: list[dict] = []

    async def accept(self) -> None:
        pass

    async def send_json(self, payload: dict) -> None:
        self.sent.append(payload)


@pytest.mark.asyncio
async def test_manager_excludes_sender() -> None:
    mgr = ConnectionManager()
    alice_ws, bob_ws = FakeSocket(), FakeSocket()

    await mgr.connect("r1", alice_ws, "alice")
    await mgr.connect("r1", bob_ws, "bob")

    await mgr.broadcast("r1", {"payload": "opaque"}, exclude=alice_ws)

    assert bob_ws.sent[-1] == {"payload": "opaque"}  # Bob reçoit
    alice_payloads = [m.get("payload") for m in alice_ws.sent]
    assert "opaque" not in alice_payloads  # L'émetteur est exclu
