"""Tests salons : liste, invitation, membres, clés enveloppées, historique.

Tous les contenus sont des blobs opaques : le serveur ne vérifie ici que les
autorisations (appartenance / propriété) et rejoue des données illisibles.
"""

import json

from conftest import InMemory, create_room, register
from starlette.testclient import TestClient

from app.main import app

_BLOB = {"v": 1, "iv": "aGVsbG8=", "ct": "d29ybGQ="}


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


def test_list_rooms_for_member(client, inmemory) -> None:
    register(client, "alice")
    rid = create_room(client, "général")
    r = client.get("/api/rooms")
    assert r.status_code == 200
    assert [room["id"] for room in r.json()] == [rid]


def test_invite_flow(inmemory: InMemory) -> None:
    alice = TestClient(app)
    bob = TestClient(app)
    with alice, bob:
        register(alice, "alice")
        rid = create_room(alice)
        register(bob, "bob")

        r = alice.post(
            f"/api/rooms/{rid}/invite",
            json={"username": "bob"},
            headers={"X-CSRF-Token": _csrf(alice)},
        )
        assert r.status_code == 200


def test_invite_only_owner_can_invite(inmemory: InMemory) -> None:
    alice = TestClient(app)
    bob = TestClient(app)
    carol = TestClient(app)
    with alice, bob, carol:
        register(alice, "alice")
        rid = create_room(alice)
        register(bob, "bob")

        alice.post(
            f"/api/rooms/{rid}/invite",
            json={"username": "bob"},
            headers={"X-CSRF-Token": _csrf(alice)},
        )
        # Bob n'est pas propriétaire : 403
        r = bob.post(
            f"/api/rooms/{rid}/invite",
            json={"username": "carol"},
            headers={"X-CSRF-Token": _csrf(bob)},
        )
        assert r.status_code == 403


def test_invite_unknown_user_404(client, inmemory) -> None:
    register(client, "alice")
    rid = create_room(client)
    r = client.post(
        f"/api/rooms/{rid}/invite",
        json={"username": "ghost"},
        headers={"X-CSRF-Token": _csrf(client)},
    )
    assert r.status_code == 404


def test_members_requires_membership(inmemory: InMemory) -> None:
    insider = TestClient(app)
    outsider = TestClient(app)
    with insider, outsider:
        register(insider, "alice")
        rid = create_room(insider)

        register(outsider, "mallory")
        assert outsider.get(f"/api/rooms/{rid}/members").status_code == 403

        r = insider.get(f"/api/rooms/{rid}/members")
        assert r.status_code == 200
        assert r.json()["owner_id"] == "alice"
        assert r.json()["members"][0]["username"] == "alice"


def test_share_and_fetch_wrapped_key(inmemory: InMemory) -> None:
    alice = TestClient(app)
    bob = TestClient(app)
    with alice, bob:
        register(alice, "alice")
        rid = create_room(alice)
        register(bob, "bob")

        alice.post(
            f"/api/rooms/{rid}/invite",
            json={"username": "bob"},
            headers={"X-CSRF-Token": _csrf(alice)},
        )
        r = alice.post(
            f"/api/rooms/{rid}/keys",
            json={"to": "bob", "blob": _BLOB},
            headers={"X-CSRF-Token": _csrf(alice)},
        )
        assert r.status_code == 204

        r = bob.get(f"/api/rooms/{rid}/keys/me")
        assert r.status_code == 200
        assert r.json() == _BLOB


def test_share_key_forbidden_for_non_owner(inmemory: InMemory) -> None:
    owner = TestClient(app)
    alice = TestClient(app)
    with owner, alice:
        register(owner, "bob")
        bid = create_room(owner)  # propriétaire : bob
        register(alice, "alice")

        csrf = _csrf(owner)
        assert (
            owner.post(
                f"/api/rooms/{bid}/invite",
                json={"username": "alice"},
                headers={"X-CSRF-Token": csrf},
            ).status_code
            == 200
        )
        r = owner.post(
            f"/api/rooms/{bid}/keys",
            json={"to": "alice", "blob": _BLOB},
            headers={"X-CSRF-Token": _csrf(owner)},
        )
        assert r.status_code == 204

        # alice (membre mais non owner) tente de partager : 403
        r = alice.post(
            f"/api/rooms/{bid}/keys",
            json={"to": "alice", "blob": _BLOB},
            headers={"X-CSRF-Token": _csrf(alice)},
        )
        assert r.status_code == 403


def test_share_key_to_non_member_rejected(inmemory: InMemory) -> None:
    alice = TestClient(app)
    bob = TestClient(app)
    with alice, bob:
        register(alice, "alice")
        rid = create_room(alice)
        register(bob, "bob")
        # bob n'est pas encore membre : refus avant tout partage
        r = alice.post(
            f"/api/rooms/{rid}/keys",
            json={"to": "bob", "blob": _BLOB},
            headers={"X-CSRF-Token": _csrf(alice)},
        )
        assert r.status_code == 400


def test_history_persists_after_ws(two_members) -> None:
    alice, bob, room_id = two_members
    cid = _channel_id(alice, room_id)

    with _connect(alice, room_id) as a_ws:
        with _connect(bob, room_id) as b_ws:
            # La présence de Bob est annoncée à Alice (jamais à Bob lui-même).
            assert a_ws.receive_json()["type"] == "presence"
            a_ws.send_text(json.dumps({"channel": cid, "payload": "blob-one"}))
            assert b_ws.receive_json()["payload"] == "blob-one"
            a_ws.send_text(json.dumps({"channel": cid, "payload": "blob-two"}))
            assert b_ws.receive_json()["payload"] == "blob-two"

    r = alice.get(f"/api/rooms/{room_id}/channels/{cid}/messages")
    assert r.status_code == 200
    msgs = r.json()
    assert [m["payload"] for m in msgs] == ["blob-one", "blob-two"]
    assert all(m["sender"] == "alice" for m in msgs)
    assert [m["n"] for m in msgs] == [1, 2]

    # Curseur "after" : lecture incrémentale (déduplication côté client)
    r = alice.get(f"/api/rooms/{room_id}/channels/{cid}/messages?after=1")
    assert [m["payload"] for m in r.json()] == ["blob-two"]


def test_history_requires_membership(inmemory: InMemory) -> None:
    insider = TestClient(app)
    outsider = TestClient(app)
    with insider, outsider:
        register(insider, "alice")
        rid = create_room(insider)
        register(outsider, "mallory")
        assert outsider.get(f"/api/rooms/{rid}/channels").status_code == 403


def test_my_wrapped_key_404_when_none(client, inmemory) -> None:
    register(client, "alice")
    rid = create_room(client)
    r = client.get(f"/api/rooms/{rid}/keys/me")
    assert r.status_code == 404
