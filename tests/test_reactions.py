"""Tests réactions : blobs chiffrés ciblant un message (« n »), agrégés
côté client. Le serveur ne connaît jamais l'emoji : juste la cible (n),
l'auteur et un blob opaque (E2EE).

Le retrait est un toggle explicite ({n} sans blob) : le serveur ne pouvant
pas comparer deux emojis chiffrés, la suppression se fait en clair côté
métadonnée (cible + auteur), jamais sur le contenu.
"""

import json

from conftest import InMemory, create_room, register
from starlette.testclient import TestClient

from app.main import app

_BLOB = {"v": 1, "iv": "aXZ4eQ==", "ct": "Y3R4eQ=="}


def _csrf(client) -> str:
    r = client.get("/api/auth/csrf")
    assert r.status_code == 200
    return r.json()["csrf_token"]


def _channel_id(client, room_id: str) -> str:
    r = client.get(f"/api/rooms/{room_id}/channels")
    assert r.status_code == 200
    return r.json()[0]["id"]


def _react(client, room_id: str, channel_id: str, n: int, blob=None):
    body = {"n": n} if blob is None else {"n": n, "blob": blob}
    return client.post(
        f"/api/rooms/{room_id}/channels/{channel_id}/reactions",
        json=body,
        headers={"X-CSRF-Token": _csrf(client)},
    )


def _reactions(client, room_id: str, channel_id: str) -> list[dict]:
    r = client.get(f"/api/rooms/{room_id}/channels/{channel_id}/reactions")
    assert r.status_code == 200
    return r.json()


def test_add_and_list_reaction(client, inmemory: InMemory) -> None:
    register(client, "alice")
    rid = create_room(client)
    cid = _channel_id(client, rid)

    r = _react(client, rid, cid, 3, _BLOB)
    assert r.status_code == 201
    row = r.json()
    assert row["n"] == 3 and row["sender"] == "alice"
    assert json.loads(row["payload"]) == _BLOB

    rows = _reactions(client, rid, cid)
    assert len(rows) == 1
    assert rows[0]["n"] == 3 and rows[0]["sender"] == "alice"


def test_reaction_upsert_replaces_same_user(inmemory: InMemory) -> None:
    alice, bob = TestClient(app), TestClient(app)
    with alice, bob:
        register(alice, "alice")
        rid = create_room(alice)
        cid = _channel_id(alice, rid)
        register(bob, "bob")
        alice.post(
            f"/api/rooms/{rid}/invite",
            json={"username": "bob"},
            headers={"X-CSRF-Token": _csrf(alice)},
        )

        assert _react(alice, rid, cid, 7, _BLOB).status_code == 201
        assert _react(bob, rid, cid, 7, _BLOB).status_code == 201
        rows = _reactions(alice, rid, cid)
        assert len(rows) == 2  # un auteur chacun, même cible

        # Alice remplace son emoji (upsert, pas de doublon).
        b2 = {"v": 1, "iv": "aXZ5eg==", "ct": "Y3R5eg=="}
        assert _react(alice, rid, cid, 7, b2).status_code == 201
        rows = _reactions(alice, rid, cid)
        assert len(rows) == 2
        alice_rows = [r for r in rows if r["sender"] == "alice"]
        assert json.loads(alice_rows[0]["payload"]) == b2


def test_reaction_toggle_removes(inmemory: InMemory) -> None:
    client = TestClient(app)
    with client:
        register(client, "alice")
        rid = create_room(client)
        cid = _channel_id(client, rid)
        _react(client, rid, cid, 5, _BLOB)
        assert len(_reactions(client, rid, cid)) == 1
        r = _react(client, rid, cid, 5)  # retrait : blob absent
        assert r.status_code == 204
        assert _reactions(client, rid, cid) == []


def test_reactions_require_membership_and_channel(inmemory: InMemory) -> None:
    insider, outsider = TestClient(app), TestClient(app)
    with insider, outsider:
        register(insider, "alice")
        rid = create_room(insider)
        cid = _channel_id(insider, rid)
        register(outsider, "mallory")

        assert outsider.get(f"/api/rooms/{rid}/channels/{cid}/reactions").status_code == 403
        r = outsider.post(
            f"/api/rooms/{rid}/channels/{cid}/reactions",
            json={"n": 1, "blob": _BLOB},
            headers={"X-CSRF-Token": _csrf(outsider)},
        )
        assert r.status_code == 403
        # Canal inconnu d'un membre : 404.
        r = insider.post(
            f"/api/rooms/{rid}/channels/inconnu/reactions",
            json={"n": 1, "blob": _BLOB},
            headers={"X-CSRF-Token": _csrf(insider)},
        )
        assert r.status_code == 404
