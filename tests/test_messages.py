"""Envoi, réception et historique des messages chiffrés.

Le point sensible de ce fichier est l'anti-rejeu par `client_id` : un client
qui n'a pas vu l'accusé de réception doit pouvoir réémettre sans créer de
doublon. C'est la raison pour laquelle l'accusé est renvoyé même en cas de
doublon détecté, et non une erreur.

Reste aussi à vérifier que le serveur ne se substitue pas à l'expéditeur :
`sender_id` provient de la session, jamais du corps de la trame. Un client qui
tente de l'imposer voit sa trame rejetée.

La diffusion à plusieurs membres est testée séparément, sur `ConnectionManager`
lui-même : le `TestClient` partage un seul cookie jar, il ne sait donc pas
incarner deux membres à la fois sur la même connexion.
"""

from __future__ import annotations

import base64
import uuid

import pytest
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

from app.deps import POLICY_VIOLATION
from tests.conftest import (
    TEST_ORIGIN,
    ciphertext_b64,
    create_channel,
    iv_b64,
    register_user,
    unique_username,
)


def open_channel_socket(client: TestClient, channel_id: str) -> object:
    return client.websocket_connect(f"/channels/{channel_id}", headers={"Origin": TEST_ORIGIN})


def send_frame(socket: object, channel_id: str, client_id: str | None = None) -> None:
    socket.send_json(  # type: ignore[attr-defined]
        {
            "type": "send",
            "channel_id": channel_id,
            "client_id": client_id or str(uuid.uuid4()),
            "iv": iv_b64(),
            "ciphertext": ciphertext_b64(),
        }
    )


def test_l_historique_vide(client: TestClient) -> None:
    register_user(client)
    channel = create_channel(client)

    response = client.get(f"/channels/{channel['id']}/messages")

    assert response.status_code == 200, response.text
    assert response.json() == {"messages": [], "has_more": False}


def test_envoyer_un_message_le_retrouve_dans_l_historique(client: TestClient) -> None:
    register_user(client)
    channel = create_channel(client)

    with open_channel_socket(client, channel["id"]) as socket:
        send_frame(socket, channel["id"])
        assert socket.receive_json()["type"] == "ack"

    response = client.get(f"/channels/{channel['id']}/messages")
    messages = response.json()["messages"]

    assert len(messages) == 1, response.text
    message = messages[0]
    # Le serveur ne fait que restituer le ciphertext : il ne l'a pas ouvert.
    assert message["ciphertext"] == ciphertext_b64()
    assert message["iv"] == iv_b64()
    assert message["sender_id"] == channel["members"][0]["id"]
    assert message["client_id"]


def test_l_emetteur_ne_recoit_pas_son_propre_message(client: TestClient) -> None:
    register_user(client)
    channel = create_channel(client)

    with open_channel_socket(client, channel["id"]) as socket:
        send_frame(socket, channel["id"])
        # Le premier cadre reçu est l'accusé, pas une rediffusion.
        assert socket.receive_json()["type"] == "ack"


def test_un_websocket_refuse_un_non_membre(client: TestClient) -> None:
    register_user(client)
    channel = create_channel(client)
    client.cookies.clear()
    register_user(client, unique_username())

    with pytest.raises(WebSocketDisconnect) as caught:
        with open_channel_socket(client, channel["id"]) as socket:
            socket.receive_json()
    assert caught.value.code == 4403


def test_un_websocket_refuse_un_canal_inexistant(client: TestClient) -> None:
    register_user(client)

    with pytest.raises(WebSocketDisconnect) as caught:
        with open_channel_socket(client, uuid.uuid4().hex[:24]) as socket:
            socket.receive_json()
    assert caught.value.code == 4404


def test_un_websocket_exige_une_session(client: TestClient) -> None:
    register_user(client)
    channel = create_channel(client)
    client.cookies.clear()

    with pytest.raises(WebSocketDisconnect) as caught:
        with open_channel_socket(client, channel["id"]):
            pass
    assert caught.value.code == POLICY_VIOLATION


def test_un_re_emission_ne_duplique_pas(client: TestClient) -> None:
    register_user(client)
    channel = create_channel(client)
    client_id = str(uuid.uuid4())

    with open_channel_socket(client, channel["id"]) as socket:
        send_frame(socket, channel["id"], client_id)
        assert socket.receive_json()["type"] == "ack"
        # Le client n'a pas vu le premier accusé : il réémet.
        send_frame(socket, channel["id"], client_id)
        replayed = socket.receive_json()
        assert replayed["type"] == "ack"
        assert replayed["duplicate"] is True

    messages = client.get(f"/channels/{channel['id']}/messages").json()["messages"]
    assert len(messages) == 1


def test_le_sender_id_vient_de_la_session(client: TestClient) -> None:
    """Un client ne peut pas attribuer un message à quelqu'un d'autre."""
    register_user(client)
    channel = create_channel(client)

    with open_channel_socket(client, channel["id"]) as socket:
        socket.send_json(
            {
                "type": "send",
                "channel_id": channel["id"],
                "client_id": str(uuid.uuid4()),
                "iv": iv_b64(),
                "ciphertext": ciphertext_b64(),
                # Champ parasite : le schéma le rejette, et aucun `sender_id`
                # soumis ne peut remplacer celui de la session.
                "sender_id": uuid.uuid4().hex[:24],
            }
        )
        assert socket.receive_json()["type"] == "error"

    assert client.get(f"/channels/{channel['id']}/messages").json()["messages"] == []


def test_une_trame_invalide_renvoie_une_erreur(client: TestClient) -> None:
    register_user(client)
    channel = create_channel(client)

    with open_channel_socket(client, channel["id"]) as socket:
        socket.send_json({"type": "send", "channel_id": channel["id"]})
        assert socket.receive_json()["type"] == "error"

        socket.send_json({"type": "subscribe", "channel_id": channel["id"]})
        # L'abonnement est implicite : la connexion porte déjà le canal.
        assert socket.receive_json()["type"] == "error"


def test_un_iv_invalide_est_refuse(client: TestClient) -> None:
    register_user(client)
    channel = create_channel(client)
    bad_iv = base64.b64encode(b"trop-court").decode("ascii")

    with open_channel_socket(client, channel["id"]) as socket:
        socket.send_json(
            {
                "type": "send",
                "channel_id": channel["id"],
                "client_id": str(uuid.uuid4()),
                "iv": bad_iv,
                "ciphertext": ciphertext_b64(),
            }
        )
        assert socket.receive_json()["type"] == "error"


def test_un_ciphertext_trop_long_est_refuse(client: TestClient) -> None:
    register_user(client)
    channel = create_channel(client)
    oversized = base64.b64encode(b"x" * 30_000).decode("ascii")

    with open_channel_socket(client, channel["id"]) as socket:
        socket.send_json(
            {
                "type": "send",
                "channel_id": channel["id"],
                "client_id": str(uuid.uuid4()),
                "iv": iv_b64(),
                "ciphertext": oversized,
            }
        )
        assert socket.receive_json()["type"] == "error"


def test_l_historique_est_pagine_par_curseur(client: TestClient) -> None:
    register_user(client)
    channel = create_channel(client)
    channel_id = channel["id"]

    with open_channel_socket(client, channel_id) as socket:
        for _ in range(5):
            send_frame(socket, channel_id)
            socket.receive_json()

    first = client.get(f"/channels/{channel_id}/messages?limit=2").json()
    assert len(first["messages"]) == 2
    assert first["has_more"] is True
    # Du plus ancien au plus récent : la page se lit telle quelle.
    assert first["messages"][0]["id"] < first["messages"][1]["id"]

    # Le curseur est le message le plus ancien déjà reçu : la page suivante
    # remonte dans le temps.
    cursor = first["messages"][0]["id"]
    second = client.get(f"/channels/{channel_id}/messages?limit=2&before={cursor}").json()
    assert len(second["messages"]) == 2
    # Aucune intersection : le curseur ne saute ni ne répète de message.
    first_ids = {message["id"] for message in first["messages"]}
    second_ids = {message["id"] for message in second["messages"]}
    assert first_ids.isdisjoint(second_ids)

    third = client.get(
        f"/channels/{channel_id}/messages?limit=2&before={second['messages'][0]['id']}"
    ).json()
    assert len(third["messages"]) == 1
    assert third["has_more"] is False


def test_un_curseur_invalide_renvoie_400(client: TestClient) -> None:
    register_user(client)
    channel = create_channel(client)
    response = client.get(f"/channels/{channel['id']}/messages?before=nimporte-quoi")
    assert response.status_code == 400, response.text


def test_un_historique_exige_l_appartenance(client: TestClient) -> None:
    register_user(client)
    channel = create_channel(client)
    client.cookies.clear()
    register_user(client, unique_username())

    response = client.get(f"/channels/{channel['id']}/messages")
    assert response.status_code == 403, response.text
