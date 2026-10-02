"""Tests des salons, canaux et messages, avec le parcours complet entre deux utilisateurs."""

import pytest

from tests.conftest import CIPHER, create_server, signup


# Parcours complet : inscription → salon → envoi → l'autre rejoint → réception → historique
def test_full_flow_between_two_users(browser, stored):
    alice, bob = browser(), browser()
    signup(alice)
    signup(bob, "bob")
    server, path = create_server(alice)
    assert alice.post(path, json=CIPHER).status_code == 200

    assert bob.post(f"/api/servers/{server['id']}/join").status_code == 200
    assert bob.get("/api/servers").json() == [{"id": server["id"], "name": "Cours"}]
    reply = {**CIPHER, "ciphertext": "cmVwb25zZS1kZS1ib2ItY2hpZmZyZWU"}
    assert bob.post(path, json=reply).status_code == 200

    history = alice.get(path).json()
    assert [message["author"] for message in history] == ["alice", "bob"]
    assert history[0]["ciphertext"] == CIPHER["ciphertext"]
    assert history[1]["ciphertext"] == reply["ciphertext"]
    # Redis ne contient que le chiffré
    assert all("text" not in message for message in history)
    assert stored.llen(f"channel:{server['channel_id']}:messages") == 2


def test_server_list_only_shows_my_servers(browser):
    alice, bob = browser(), browser()
    signup(alice)
    signup(bob, "bob")
    create_server(alice, "Zèbre")
    create_server(alice, "alpha")
    create_server(bob, "Privé")
    assert [server["name"] for server in alice.get("/api/servers").json()] == ["alpha", "Zèbre"]


def test_non_member_is_refused(browser):
    alice, bob = browser(), browser()
    signup(alice)
    signup(bob, "bob")
    server, path = create_server(alice)
    assert bob.get(f"/api/servers/{server['id']}/channels").status_code == 403
    assert bob.get(path).status_code == 403
    assert bob.post(path, json=CIPHER).status_code == 403


def test_logged_out_user_is_refused(browser):
    alice, visitor = browser(), browser()
    signup(alice)
    server, path = create_server(alice)
    assert visitor.get("/api/servers").status_code == 401
    assert visitor.get(path).status_code == 401
    assert visitor.post(f"/api/servers/{server['id']}/join").status_code == 401


def test_only_owner_can_add_a_channel(browser):
    alice, bob = browser(), browser()
    signup(alice)
    signup(bob, "bob")
    server, _ = create_server(alice)
    bob.post(f"/api/servers/{server['id']}/join")
    channels_path = f"/api/servers/{server['id']}/channels"
    assert bob.post(channels_path, json={"name": "Pirate"}).status_code == 403
    assert alice.post(channels_path, json={"name": "  Devoirs  "}).json()["name"] == "Devoirs"
    assert [channel["name"] for channel in bob.get(channels_path).json()] == ["général", "Devoirs"]


def test_channel_must_belong_to_server(client):
    signup(client)
    first, _ = create_server(client, "Premier")
    second, _ = create_server(client, "Second")
    path = f"/api/servers/{first['id']}/channels/{second['channel_id']}/messages"
    assert client.get(path).status_code == 404
    assert client.post(path, json=CIPHER).status_code == 404


def test_unknown_server_is_not_found(client):
    signup(client)
    assert client.post("/api/servers/inconnu/join").status_code == 404
    assert client.get("/api/servers/inconnu/channels").status_code == 404


@pytest.mark.parametrize("name", ["", "   ", "x" * 41])
def test_bad_names_are_rejected(client, name):
    signup(client)
    assert client.post("/api/servers", json={"name": name}).status_code == 422


@pytest.mark.parametrize("message", [
    {"text": "secret en clair"},
    {**CIPHER, "text": "secret en clair"},
    {**CIPHER, "version": 2},
    {**CIPHER, "nonce": "trop-court"},
    {**CIPHER, "ciphertext": "pas du base64 <script>!!"},
    {**CIPHER, "ciphertext": "x" * 12001},
])
def test_plain_or_broken_messages_are_rejected(client, message):
    signup(client)
    _, path = create_server(client)
    assert client.post(path, json=message).status_code == 422


def test_history_keeps_the_last_100_messages(client):
    signup(client)
    _, path = create_server(client)
    for number in range(105):
        client.post(path, json={**CIPHER, "ciphertext": f"{CIPHER['ciphertext']}{number:03d}"})
    history = client.get(path).json()
    assert len(history) == 100
    assert history[0]["ciphertext"].endswith("005")
    assert history[-1]["ciphertext"].endswith("104")
