"""QA intégration WebSocket : broadcast de blobs aléatoires (chiffrés simulés).

Les payloads sont OP AQUES : on envoie des octets aléatoires encodés en base64
(et un authentique blob JSON {v, iv, ct}) ; le serveur ne doit ni les lire ni
les modifier — seulement les distribuer aux autres membres.
"""

import base64
import json
import os

import pytest
from conftest import InMemory, create_room, register
from starlette.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

from app.main import app

MAX_PAYLOAD_BYTES = 64 * 1024


def _csrf(client) -> str:
    r = client.get("/api/auth/csrf")
    assert r.status_code == 200
    return r.json()["csrf_token"]


def _connect(client, room_id: str):
    return client.websocket_connect(f"/api/ws?room_id={room_id}")


def _channel_id(client, room_id: str) -> str:
    r = client.get(f"/api/rooms/{room_id}/channels")
    assert r.status_code == 200
    return r.json()[0]["id"]  # `general` créé automatiquement


def _random_blob(size: int = 48) -> str:
    """Octets aléatoires encodés en base64 : un chiffré plausible."""
    return base64.b64encode(os.urandom(size)).decode("ascii")


def _json_cipher_blob() -> str:
    """Blob au vrai format client {v, iv, ct} — toujours opaque pour le serveur."""
    return json.dumps(
        {
            "v": 1,
            "iv": base64.b64encode(os.urandom(12)).decode(),
            "ct": base64.b64encode(os.urandom(64)).decode(),
        }
    )


def test_broadcast_random_blobs_to_all_but_sender(inmemory: InMemory) -> None:
    """3 membres ; l'émetteur ne reçoit jamais ses blobs, les 2 autres si."""
    alice, bob, carol = TestClient(app), TestClient(app), TestClient(app)
    with alice, bob, carol:
        register(alice, "alice")
        rid = create_room(alice)
        register(bob, "bob")
        register(carol, "carol")

        csrf = _csrf(alice)
        for who in ("bob", "carol"):
            r = alice.post(
                f"/api/rooms/{rid}/invite",
                json={"username": who},
                headers={"X-CSRF-Token": csrf},
            )
            assert r.status_code == 200
        cid = _channel_id(alice, rid)

        with _connect(alice, rid) as a_ws:
            with _connect(bob, rid) as b_ws:
                with _connect(carol, rid) as c_ws:
                    # Présence (déterministe) : alice voit bob puis carol, bob voit carol.
                    assert a_ws.receive_json()["event"] == "join"
                    assert a_ws.receive_json()["event"] == "join"
                    assert b_ws.receive_json()["event"] == "join"

                    blobs = [_random_blob(16 + i) for i in range(3)]
                    blobs.append(_json_cipher_blob())
                    for i, blob in enumerate(blobs, start=1):
                        a_ws.send_text(json.dumps({"channel": cid, "payload": blob}))
                        for ws in (b_ws, c_ws):
                            msg = ws.receive_json()
                            assert msg["payload"] == blob
                            assert msg["channel_id"] == cid
                            assert msg["from"] == "alice"
                            assert msg["n"] == i

                    blob_b = _random_blob(32)
                    b_ws.send_text(json.dumps({"channel": cid, "payload": blob_b}))
                    for ws in (a_ws, c_ws):
                        msg = ws.receive_json()
                        assert msg["payload"] == blob_b
                        assert msg["from"] == "bob"


def test_ws_rejects_oversized_payload_without_broadcast(two_members) -> None:
    """Au-delà du plafond, le blob est refusé (4409) et JAMAIS distribué."""
    alice, bob, room_id = two_members
    cid = _channel_id(alice, room_id)
    with _connect(alice, room_id) as a_ws:
        with _connect(bob, room_id) as b_ws:
            assert a_ws.receive_json()["type"] == "presence"
            big = "A" * (MAX_PAYLOAD_BYTES + 1)
            a_ws.send_text(json.dumps({"channel": cid, "payload": big}))

            with pytest.raises(WebSocketDisconnect) as exc:
                a_ws.receive_json()
            assert exc.value.code == 4409

            # Bob reçoit le « leave » de présence, PAS le payload géant.
            msg = b_ws.receive_json()
            assert msg["type"] == "presence"
            assert msg["event"] == "leave"
            assert "payload" not in msg


def test_random_blobs_persisted_to_history(two_members) -> None:
    """Les blobs aléatoires passent par la persistance et reviennent intacts."""
    alice, bob, room_id = two_members
    cid = _channel_id(alice, room_id)
    blobs = [_random_blob(24) for _ in range(2)]
    blobs.append(_json_cipher_blob())

    with _connect(alice, room_id) as a_ws:
        with _connect(bob, room_id) as b_ws:
            assert a_ws.receive_json()["type"] == "presence"
            for blob in blobs:
                a_ws.send_text(json.dumps({"channel": cid, "payload": blob}))
                assert b_ws.receive_json()["payload"] == blob

    r = alice.get(f"/api/rooms/{room_id}/channels/{cid}/messages")
    assert r.status_code == 200
    payloads = [m["payload"] for m in r.json()]
    assert payloads == blobs
    assert all(m["sender"] == "alice" for m in r.json())


def test_ws_nosql_shaped_room_id_rejected(client, inmemory) -> None:
    """room_id au format opérateur NoSQL -> refus propre, pas de crash."""
    register(client, "alice")
    with pytest.raises(WebSocketDisconnect) as exc:
        with _connect(client, "$ne"):
            pass
    assert exc.value.code == 4401


def test_ws_overlong_room_id_rejected(client, inmemory) -> None:
    register(client, "alice")
    with pytest.raises(WebSocketDisconnect):
        with _connect(client, "x" * 65):
            pass
