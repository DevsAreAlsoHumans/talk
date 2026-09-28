"""Tests canaux (modèle Discord) : CRUD, isolation des fils, enveloppe WS.

Un canal = un fil textuel chiffré dans un salon. Les messages sont isolés par
canal (seq indépendante) et le WS refuse toute enveloppe qui ne cible pas un
canal du salon courant (anti-crosstalk multi-salons).
"""

import json

import pytest
from conftest import InMemory, create_channel, create_room, register
from starlette.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

from app.main import app


def _csrf(client) -> str:
    r = client.get("/api/auth/csrf")
    assert r.status_code == 200
    return r.json()["csrf_token"]


def _connect(client, room_id: str):
    return client.websocket_connect(f"/api/ws?room_id={room_id}")


def _channels(client, room_id: str) -> list[dict]:
    r = client.get(f"/api/rooms/{room_id}/channels")
    assert r.status_code == 200
    return r.json()


def test_room_starts_with_general_channel(client) -> None:
    register(client, "alice")
    rid = create_room(client)
    assert [c["name"] for c in _channels(client, rid)] == ["general"]


def test_create_new_channel(client) -> None:
    register(client, "alice")
    rid = create_room(client)
    cid = create_channel(client, rid, "règles")
    names = [c["name"] for c in _channels(client, rid)]
    assert names == ["general", "règles"]
    assert _channels(client, rid)[1]["id"] == cid


@pytest.mark.parametrize("name", ["li\nne", "a\tb", "\x00x", "ADMIN", "  SYSTEM  ", "x" * 65])
def test_create_channel_rejects_injections(client, name) -> None:
    register(client, "alice")
    rid = create_room(client)
    r = client.post(
        f"/api/rooms/{rid}/channels",
        json={"name": name},
        headers={"X-CSRF-Token": _csrf(client)},
    )
    assert r.status_code == 422


def test_create_channel_strips_whitespace(client) -> None:
    register(client, "alice")
    rid = create_room(client)
    r = client.post(
        f"/api/rooms/{rid}/channels",
        json={"name": "  news  "},
        headers={"X-CSRF-Token": _csrf(client)},
    )
    assert r.status_code == 201
    assert r.json()["name"] == "news"


def test_duplicate_channel_name_409(client) -> None:
    register(client, "alice")
    rid = create_room(client)
    r = client.post(
        f"/api/rooms/{rid}/channels",
        json={"name": "general"},  # déjà créé automatiquement
        headers={"X-CSRF-Token": _csrf(client)},
    )
    assert r.status_code == 409


def test_channels_require_membership(inmemory: InMemory) -> None:
    insider, outsider = TestClient(app), TestClient(app)
    with insider, outsider:
        register(insider, "alice")
        rid = create_room(insider)
        register(outsider, "mallory")

        assert outsider.get(f"/api/rooms/{rid}/channels").status_code == 403
        r = outsider.post(
            f"/api/rooms/{rid}/channels",
            json={"name": "pirate"},
            headers={"X-CSRF-Token": _csrf(outsider)},
        )
        assert r.status_code == 403


def test_messages_isolated_per_channel(two_members) -> None:
    alice, bob, room_id = two_members
    general = _channels(alice, room_id)[0]["id"]
    extra = create_channel(alice, room_id, "privé")

    with _connect(alice, room_id) as a_ws:
        with _connect(bob, room_id) as b_ws:
            assert a_ws.receive_json()["type"] == "presence"

            a_ws.send_text(json.dumps({"channel": general, "payload": "sur-general"}))
            assert b_ws.receive_json()["payload"] == "sur-general"

            a_ws.send_text(json.dumps({"channel": extra, "payload": "sur-prive"}))
            msg = b_ws.receive_json()
            assert msg["channel_id"] == extra
            assert msg["payload"] == "sur-prive"

    r1 = alice.get(f"/api/rooms/{room_id}/channels/{general}/messages")
    r2 = alice.get(f"/api/rooms/{room_id}/channels/{extra}/messages")
    assert [m["payload"] for m in r1.json()] == ["sur-general"]
    assert [m["payload"] for m in r2.json()] == ["sur-prive"]
    assert r1.json()[0]["n"] == 1  # seq indépendante par canal
    assert r2.json()[0]["n"] == 1


def test_messages_require_membership_and_404(client, inmemory: InMemory) -> None:
    register(client, "alice")
    rid = create_room(client)
    general = _channels(client, rid)[0]["id"]

    assert client.get(f"/api/rooms/{rid}/channels/xyz/messages").status_code == 404

    outsider = TestClient(app)
    with outsider:
        register(outsider, "mallory")
        assert (
            outsider.get(f"/api/rooms/{rid}/channels/{general}/messages").status_code == 403
        )


def test_ws_bad_envelope_closes(two_members) -> None:
    alice, bob, room_id = two_members
    with _connect(alice, room_id) as a_ws:
        with _connect(bob, room_id) as b_ws:
            assert a_ws.receive_json()["type"] == "presence"
            a_ws.send_text("pas du json")
            with pytest.raises(WebSocketDisconnect) as exc:
                a_ws.receive_json()
            assert exc.value.code == 4402
            # Alice est évacuée du salon : Bob voit son départ, pas de payload.
            msg = b_ws.receive_json()
            assert msg["type"] == "presence" and msg["event"] == "leave"


def test_ws_unknown_channel_closes(two_members) -> None:
    alice, _, room_id = two_members
    with _connect(alice, room_id) as a_ws:
        a_ws.send_text(json.dumps({"channel": "inconnu", "payload": "x"}))
        with pytest.raises(WebSocketDisconnect) as exc:
            a_ws.receive_json()
        assert exc.value.code == 4402


def test_ws_rejects_channel_of_another_room(inmemory: InMemory) -> None:
    """Un membre du salon A ne peut pas injecter dans un canal du salon B."""
    alice, bob = TestClient(app), TestClient(app)
    with alice, bob:
        register(alice, "alice")
        ra = create_room(alice)
        rb = create_room(alice)
        register(bob, "bob")
        csrf = _csrf(alice)
        for rid in (ra, rb):
            r = alice.post(
                f"/api/rooms/{rid}/invite",
                json={"username": "bob"},
                headers={"X-CSRF-Token": csrf},
            )
            assert r.status_code == 200

        channel_b = _channels(alice, rb)[0]["id"]

        with _connect(alice, ra) as a_ws:
            a_ws.send_text(json.dumps({"channel": channel_b, "payload": "fuite?"}))
            with pytest.raises(WebSocketDisconnect) as exc:
                a_ws.receive_json()
            assert exc.value.code == 4402

        # Le canal B n'a rien reçu : le blob n'a jamais été persisté.
        msgs = alice.get(f"/api/rooms/{rb}/channels/{channel_b}/messages")
        assert msgs.json() == []


def test_delete_channel_by_owner(two_members) -> None:
    alice, bob, room_id = two_members
    extra = create_channel(alice, room_id, "tmp")
    r = alice.delete(
        f"/api/rooms/{room_id}/channels/{extra}",
        headers={"X-CSRF-Token": _csrf(alice)},
    )
    assert r.status_code == 204
    assert [c["name"] for c in _channels(alice, room_id)] == ["general"]


def test_delete_channel_forbidden_for_non_owner(two_members) -> None:
    alice, bob, room_id = two_members
    general = _channels(alice, room_id)[0]["id"]
    r = bob.delete(
        f"/api/rooms/{room_id}/channels/{general}",
        headers={"X-CSRF-Token": _csrf(bob)},
    )
    assert r.status_code == 403


def test_cannot_delete_last_channel(two_members) -> None:
    alice, bob, room_id = two_members
    general = _channels(alice, room_id)[0]["id"]
    r = alice.delete(
        f"/api/rooms/{room_id}/channels/{general}",
        headers={"X-CSRF-Token": _csrf(alice)},
    )
    assert r.status_code == 400


def test_delete_unknown_channel_404(two_members) -> None:
    alice, bob, room_id = two_members
    r = alice.delete(
        f"/api/rooms/{room_id}/channels/nope",
        headers={"X-CSRF-Token": _csrf(alice)},
    )
    assert r.status_code == 404
