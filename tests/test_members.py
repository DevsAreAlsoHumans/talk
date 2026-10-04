"""Tests des clés publiques et de la gestion des membres d'un salon."""

import pytest

from tests.conftest import PUBLIC_KEY, WRAPPED_KEY, add_member, create_server, signup

# ---------- Clés publiques ----------

def test_public_key_is_saved_and_shared(browser):
    alice, bob = browser(), browser()
    signup(alice)
    signup(bob, "bob")
    assert alice.get("/api/me").json() == {"username": "alice", "public_key": None}
    assert alice.put("/api/me/public-key", json={"public_key": PUBLIC_KEY}).status_code == 200
    assert alice.get("/api/me").json()["public_key"] == PUBLIC_KEY
    assert bob.get("/api/users/ALICE/public-key").json() == {"username": "alice", "public_key": PUBLIC_KEY}


def test_public_key_errors(browser):
    alice, visitor = browser(), browser()
    signup(alice)
    signup(alice, "bob")
    # Bob ne s'est jamais connecté depuis un navigateur : pas encore de clé
    assert alice.get("/api/users/bob/public-key").status_code == 404
    assert alice.get("/api/users/inconnu/public-key").status_code == 404
    assert alice.get("/api/users/bob:*/public-key").status_code == 422
    assert visitor.get("/api/users/bob/public-key").status_code == 401


@pytest.mark.parametrize("public_key", ["court", "P" * 1001, "P" * 300 + "<script>", {"$gt": ""}])
def test_bad_public_keys_are_rejected(client, public_key):
    signup(client)
    assert client.put("/api/me/public-key", json={"public_key": public_key}).status_code == 422


def test_public_key_needs_csrf(client):
    signup(client)
    del client.headers["X-CSRF-Token"]
    assert client.put("/api/me/public-key", json={"public_key": PUBLIC_KEY}).status_code == 403


# ---------- Membres ----------

def test_members_list(browser):
    alice, bob = browser(), browser()
    signup(alice)
    signup(bob, "bob")
    server, _ = create_server(alice)
    add_member(alice, server["id"], "Bob")
    expected = [{"username": "alice", "owner": True}, {"username": "bob", "owner": False}]
    assert alice.get(f"/api/servers/{server['id']}/members").json() == expected
    assert bob.get(f"/api/servers/{server['id']}/members").json() == expected


def test_only_owner_manages_members(browser):
    alice, bob, carol = browser(), browser(), browser()
    signup(alice)
    signup(bob, "bob")
    signup(carol, "carol")
    server, _ = create_server(alice)
    add_member(alice, server["id"], "bob")
    assert add_member(bob, server["id"], "carol").status_code == 403
    assert bob.delete(f"/api/servers/{server['id']}/members/alice").status_code == 403
    assert add_member(carol, server["id"], "carol").status_code == 403


def test_add_unknown_user(client):
    signup(client)
    server, _ = create_server(client)
    assert add_member(client, server["id"], "fantome").status_code == 404


def test_adding_again_replaces_the_key(browser):
    alice, bob = browser(), browser()
    signup(alice)
    signup(bob, "bob")
    server, _ = create_server(alice)
    add_member(alice, server["id"], "bob", "A" * 342)
    add_member(alice, server["id"], "bob", "N" * 342)
    assert bob.get(f"/api/servers/{server['id']}/key").json() == {"wrapped_key": "N" * 342}
    assert len(alice.get(f"/api/servers/{server['id']}/members").json()) == 2


def test_removed_member_loses_access_and_key(browser, stored):
    alice, bob = browser(), browser()
    signup(alice)
    signup(bob, "bob")
    server, path = create_server(alice)
    add_member(alice, server["id"], "bob")
    assert alice.delete(f"/api/servers/{server['id']}/members/bob").status_code == 200
    assert bob.get("/api/servers").json() == []
    assert bob.get(path).status_code == 403
    assert bob.get(f"/api/servers/{server['id']}/key").status_code == 403
    assert stored.hkeys(f"server:{server['id']}:keys") == [stored.get("username:alice")]


def test_owner_cannot_be_removed(client):
    signup(client)
    server, _ = create_server(client)
    assert client.delete(f"/api/servers/{server['id']}/members/alice").status_code == 400


def test_remove_someone_not_in_the_server(browser):
    alice, bob = browser(), browser()
    signup(alice)
    signup(bob, "bob")
    server, _ = create_server(alice)
    assert alice.delete(f"/api/servers/{server['id']}/members/bob").status_code == 404
    assert alice.delete(f"/api/servers/{server['id']}/members/fantome").status_code == 404


def test_server_only_stores_wrapped_keys(client, stored):
    signup(client)
    server, _ = create_server(client)
    assert stored.hvals(f"server:{server['id']}:keys") == [WRAPPED_KEY]


def test_member_without_key_gets_a_clear_error(client, stored):
    signup(client)
    server, _ = create_server(client)
    stored.delete(f"server:{server['id']}:keys")
    assert client.get(f"/api/servers/{server['id']}/key").status_code == 404
