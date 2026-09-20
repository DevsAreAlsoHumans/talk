"""Tests salons directs (message privé) : création idempotente, membres exacts."""

from conftest import register
from starlette.testclient import TestClient


def _csrf(client: TestClient) -> str:
    return client.get("/api/auth/csrf").json()["csrf_token"]


def test_direct_room_created_between_two_members(two_members) -> None:
    alice, bob, _ = two_members

    headers = {"X-CSRF-Token": _csrf(alice)}
    r = alice.post("/api/rooms/direct", json={"peer": "bob"}, headers=headers)
    assert r.status_code == 201
    room = r.json()
    assert room["owner_id"] == "alice"

    # Les deux sont membres (salon à exactement 2 membres).
    members = alice.get(f"/api/rooms/{room['id']}/members").json()["members"]
    assert {m["username"] for m in members} == {"alice", "bob"}

    # Bob voit le salon privé dans sa liste.
    assert room["id"] in [x["id"] for x in bob.get("/api/rooms").json()]


def test_direct_room_idempotent(two_members) -> None:
    alice, _, _ = two_members
    headers = {"X-CSRF-Token": _csrf(alice)}
    first = alice.post("/api/rooms/direct", json={"peer": "bob"}, headers=headers).json()
    second = alice.post("/api/rooms/direct", json={"peer": "bob"}, headers=headers).json()
    assert first["id"] == second["id"], "ne doit PAS dupliquer le salon privé"


def test_direct_room_self_rejected(two_members) -> None:
    alice, _, _ = two_members
    headers = {"X-CSRF-Token": _csrf(alice)}
    r = alice.post("/api/rooms/direct", json={"peer": "alice"}, headers=headers)
    assert r.status_code == 400


def test_direct_room_unknown_user_404(two_members) -> None:
    alice, _, _ = two_members
    headers = {"X-CSRF-Token": _csrf(alice)}
    r = alice.post("/api/rooms/direct", json={"peer": "fantome"}, headers=headers)
    assert r.status_code == 404


def test_direct_mutations_require_csrf(client: TestClient) -> None:
    register(client, "alice")
    assert client.post("/api/rooms/direct", json={"peer": "bob"}).status_code == 403
