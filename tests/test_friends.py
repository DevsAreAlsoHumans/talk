"""Tests du système d'amis : demandes, acceptation, listes, retrait, CSRF."""

from conftest import register
from starlette.testclient import TestClient


def _csrf(client: TestClient) -> str:
    return client.get("/api/auth/csrf").json()["csrf_token"]


def test_full_friendship_flow(two_members) -> None:
    alice, bob, _ = two_members

    # Alice envoie une demande à Bob.
    r = alice.post(
        "/api/friends/requests",
        json={"peer": "bob"},
        headers={"X-CSRF-Token": _csrf(alice)},
    )
    assert r.status_code == 201
    assert r.json()["username"] == "bob"
    assert r.json()["status"] == "pending"
    assert r.json()["requested_by"] == "alice"

    # Bob voit la demande entrante...
    reqs = bob.get("/api/friends/requests")
    assert reqs.status_code == 200
    body = reqs.json()
    assert any(x["username"] == "alice" and x["requested_by"] == "alice" for x in body)

    # ...mais ne figure pas encore dans ses amis.
    assert bob.get("/api/friends").json() == []

    # Acception par Bob -> relation active des deux côtés.
    r = bob.post("/api/friends/requests/alice/accept", headers={"X-CSRF-Token": _csrf(bob)})
    assert r.status_code == 200
    assert r.json()["status"] == "accepted"

    assert bob.get("/api/friends").json()[0]["username"] == "alice"
    assert alice.get("/api/friends").json()[0]["username"] == "bob"

    # Retrait par Alice : relation supprimée (idempotent).
    r = alice.delete("/api/friends/bob", headers={"X-CSRF-Token": _csrf(alice)})
    assert r.status_code == 204
    assert bob.get("/api/friends").json() == []


def test_self_friend_request_rejected(two_members) -> None:
    alice, _, _ = two_members
    r = alice.post(
        "/api/friends/requests",
        json={"peer": "alice"},
        headers={"X-CSRF-Token": _csrf(alice)},
    )
    assert r.status_code == 400


def test_friend_request_unknown_user_404(two_members) -> None:
    alice, _, _ = two_members
    r = alice.post(
        "/api/friends/requests",
        json={"peer": "inconnu"},
        headers={"X-CSRF-Token": _csrf(alice)},
    )
    assert r.status_code == 404


def test_duplicate_friend_request_409(two_members) -> None:
    alice, _, _ = two_members
    headers = {"X-CSRF-Token": _csrf(alice)}
    assert (
        alice.post("/api/friends/requests", json={"peer": "bob"}, headers=headers).status_code
        == 201
    )
    # La demande inverse (Bob -> Alice) est aussi bloquée : une seule relation.
    _, bob, _ = two_members
    r = bob.post(
        "/api/friends/requests",
        json={"peer": "alice"},
        headers={"X-CSRF-Token": _csrf(bob)},
    )
    assert r.status_code == 409


def test_requester_cannot_accept_own_request(two_members) -> None:
    alice, bob, _ = two_members
    alice.post(
        "/api/friends/requests",
        json={"peer": "bob"},
        headers={"X-CSRF-Token": _csrf(alice)},
    )
    r = alice.post("/api/friends/requests/bob/accept", headers={"X-CSRF-Token": _csrf(alice)})
    assert r.status_code == 400


def test_accept_unknown_request_404(two_members) -> None:
    alice, _, _ = two_members
    r = alice.post("/api/friends/requests/zoe/accept", headers={"X-CSRF-Token": _csrf(alice)})
    assert r.status_code == 404


def test_friends_require_auth(anonymous: TestClient) -> None:
    assert anonymous.get("/api/friends").status_code == 401
    assert anonymous.post(
        "/api/friends/requests", json={"peer": "alice"}, headers={"X-CSRF-Token": "x"}
    ).status_code == 401


def test_friend_mutations_require_csrf(client: TestClient) -> None:
    register(client, "alice")
    assert client.post("/api/friends/requests", json={"peer": "bob"}).status_code == 403
    assert client.delete("/api/friends/bob").status_code == 403


def test_friend_requests_reject_no_sql_names(two_members) -> None:
    alice, _, _ = two_members
    for evil in ("$ne", "a<b>", "x;drop", "user name"):
        r = alice.post(
            "/api/friends/requests",
            json={"peer": evil},
            headers={"X-CSRF-Token": _csrf(alice)},
        )
        assert r.status_code in (422, 404), f"{evil!r} doit être rejeté"
