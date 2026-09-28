"""Tests salons : liste, invitation, membres, clés enveloppées, historique.

Tous les contenus sont des blobs opaques : le serveur ne vérifie ici que les
autorisations (appartenance / propriété) et rejoue des données illisibles.
"""

import json

from conftest import InMemory, create_channel, create_room, register
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


def test_members_report_online_status(inmemory: InMemory) -> None:
    """Le panneau « membres » lit `online` depuis les sockets connectées."""
    alice, bob = TestClient(app), TestClient(app)
    with alice, bob:
        register(alice, "alice")
        rid = create_room(alice)
        register(bob, "bob")
        alice.post(
            f"/api/rooms/{rid}/invite",
            json={"username": "bob"},
            headers={"X-CSRF-Token": _csrf(alice)},
        )

        def online_names():
            rows = alice.get(f"/api/rooms/{rid}/members").json()["members"]
            return {m["username"] for m in rows if m["online"]}

        assert online_names() == set()

        with _connect(alice, rid) as a_ws:
            assert online_names() == {"alice"}
            with _connect(bob, rid):
                a_ws.receive_json()  # présence de Bob, queue nettoyée
                assert online_names() == {"alice", "bob"}


def test_invite_broadcasts_invited_event(inmemory: InMemory) -> None:
    """Une invite salon est annoncée UNE fois, à tous (l'inviteur compris)."""
    alice, bob, carol = TestClient(app), TestClient(app), TestClient(app)
    with alice, bob, carol:
        register(alice, "alice")
        rid = create_room(alice)
        register(bob, "bob")
        register(carol, "carol")
        alice.post(
            f"/api/rooms/{rid}/invite",
            json={"username": "bob"},
            headers={"X-CSRF-Token": _csrf(alice)},
        )

        with _connect(alice, rid) as a_ws:
            with _connect(bob, rid) as b_ws:
                a_ws.receive_json()  # présence de Bob
                r = alice.post(
                    f"/api/rooms/{rid}/invite",
                    json={"username": "carol"},
                    headers={"X-CSRF-Token": _csrf(alice)},
                )
                assert r.status_code == 200
                for ws in (a_ws, b_ws):
                    msg = ws.receive_json()
                    assert msg["type"] == "presence"
                    assert msg["event"] == "invited"
                    assert msg["user"] == "carol"


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


def test_member_leaves_room(two_members, inmemory) -> None:
    alice, bob, room_id = two_members
    assert (
        alice.post(
            f"/api/rooms/{room_id}/keys",
            json={"to": "bob", "blob": _BLOB},
            headers={"X-CSRF-Token": _csrf(alice)},
        ).status_code
        == 204
    )
    r = bob.delete(f"/api/rooms/{room_id}/members/me", headers={"X-CSRF-Token": _csrf(bob)})
    assert r.status_code == 204

    # Bob n'est plus membre : panneau membres, clés, salons — tout est refusé.
    assert bob.get(f"/api/rooms/{room_id}/members").status_code == 403
    assert bob.get(f"/api/rooms/{room_id}/keys/me").status_code == 403
    assert all(room["id"] != room_id for room in bob.get("/api/rooms").json())

    # Alice voit Bob disparaître du panneau ; sa clé enveloppée est purgée.
    names = {m["username"] for m in alice.get(f"/api/rooms/{room_id}/members").json()["members"]}
    assert names == {"alice"}
    assert (room_id, "bob") not in inmemory.wrapped


def test_leave_broadcasts_member_left(two_members) -> None:
    alice, bob, room_id = two_members
    with _connect(alice, room_id) as a_ws:
        with _connect(bob, room_id):
            a_ws.receive_json()  # présence de Bob, queue nettoyée
            r = bob.delete(
                f"/api/rooms/{room_id}/members/me",
                headers={"X-CSRF-Token": _csrf(bob)},
            )
            assert r.status_code == 204
            msg = a_ws.receive_json()
            assert msg["type"] == "presence"
            assert msg["event"] == "member_left"
            assert msg["user"] == "bob"


def test_owner_cannot_leave_shared_room(two_members) -> None:
    alice, bob, room_id = two_members
    r = alice.delete(f"/api/rooms/{room_id}/members/me", headers={"X-CSRF-Token": _csrf(alice)})
    assert r.status_code == 403


def test_owner_alone_leaving_deletes_room(two_members, inmemory) -> None:
    alice, bob, room_id = two_members
    # Bob part : Alice reste seule, elle peut alors quitter = supprimer.
    bob.delete(f"/api/rooms/{room_id}/members/me", headers={"X-CSRF-Token": _csrf(bob)})
    r = alice.delete(f"/api/rooms/{room_id}/members/me", headers={"X-CSRF-Token": _csrf(alice)})
    assert r.status_code == 204
    assert alice.get("/api/rooms").json() == []
    assert inmemory.channels == []
    assert all(rid != room_id for (rid, _user) in inmemory.wrapped)


def test_owner_deletes_room_with_members(two_members, inmemory) -> None:
    alice, bob, room_id = two_members
    _ = create_channel(alice, room_id, "tmp")
    assert (
        alice.post(
            f"/api/rooms/{room_id}/keys",
            json={"to": "bob", "blob": _BLOB},
            headers={"X-CSRF-Token": _csrf(alice)},
        ).status_code
        == 204
    )
    r = alice.delete(f"/api/rooms/{room_id}", headers={"X-CSRF-Token": _csrf(alice)})
    assert r.status_code == 204
    # Disparu pour tout le monde, y compris ses canaux et clés.
    assert alice.get("/api/rooms").json() == []
    assert bob.get("/api/rooms").json() == []
    assert bob.get(f"/api/rooms/{room_id}/members").status_code == 404
    assert (room_id, "bob") not in inmemory.wrapped


def test_delete_room_forbidden_for_non_owner(two_members) -> None:
    alice, bob, room_id = two_members
    r = bob.delete(f"/api/rooms/{room_id}", headers={"X-CSRF-Token": _csrf(bob)})
    assert r.status_code == 403


def test_transfer_ownership(two_members) -> None:
    alice, bob, room_id = two_members
    r = alice.post(
        f"/api/rooms/{room_id}/transfer",
        json={"to": "bob"},
        headers={"X-CSRF-Token": _csrf(alice)},
    )
    assert r.status_code == 204
    assert alice.get(f"/api/rooms/{room_id}/members").json()["owner_id"] == "bob"
    # Le nouveau créateur peut à son tour inviter.
    carol = TestClient(app)
    with carol:
        register(carol, "carol")
        r = bob.post(
            f"/api/rooms/{room_id}/invite",
            json={"username": "carol"},
            headers={"X-CSRF-Token": _csrf(bob)},
        )
        assert r.status_code == 200


def test_transfer_broadcasts_ownership_changed(two_members) -> None:
    alice, bob, room_id = two_members
    with _connect(alice, room_id) as a_ws:
        with _connect(bob, room_id) as b_ws:
            a_ws.receive_json()  # présence de Bob
            alice.post(
                f"/api/rooms/{room_id}/transfer",
                json={"to": "bob"},
                headers={"X-CSRF-Token": _csrf(alice)},
            )
            for ws in (a_ws, b_ws):
                msg = ws.receive_json()
                assert msg["type"] == "presence"
                assert msg["event"] == "ownership_changed"
                assert msg["owner"] == "bob"


def test_transfer_guardrails(two_members, inmemory) -> None:
    alice, bob, room_id = two_members
    # Non-créateur : 403. Cible hors du salon : 400. Transférer à soi : 400.
    assert (
        bob.post(
            f"/api/rooms/{room_id}/transfer",
            json={"to": "alice"},
            headers={"X-CSRF-Token": _csrf(bob)},
        ).status_code
        == 403
    )
    assert (
        alice.post(
            f"/api/rooms/{room_id}/transfer",
            json={"to": "ghost"},
            headers={"X-CSRF-Token": _csrf(alice)},
        ).status_code
        == 400
    )
    assert (
        alice.post(
            f"/api/rooms/{room_id}/transfer",
            json={"to": "alice"},
            headers={"X-CSRF-Token": _csrf(alice)},
        ).status_code
        == 400
    )
