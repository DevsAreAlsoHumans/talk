"""Conversations directes : création entre amis, chiffrement de bout en bout, messages."""

from tests.helpers import e2e
from tests.helpers.redis_dump import dump_redis


def test_friends_open_a_conversation_and_message_each_other(alice, bob, raw_redis):
    bob.send_friend_request(alice)
    alice.accept_friend(bob)

    conv_id = alice.create_conversation(bob)
    assert bob.load_conv_key(conv_id) == alice.conv_keys[conv_id]

    convs = alice.conv_list()
    assert [conv["id"] for conv in convs] == [conv_id]
    assert [conv["peer"]["username"] for conv in convs] == ["bob"]

    assert alice.conv_send(conv_id, "salut bob").status_code == 201
    assert bob.conv_send(conv_id, "salut alice").status_code == 201
    assert alice.read_conv(conv_id) == ["salut bob", "salut alice"]
    assert bob.read_conv(conv_id) == ["salut bob", "salut alice"]

    # Le serveur n'a jamais vu le texte en clair ni la clé de conversation.
    dump = dump_redis(raw_redis)
    assert "salut bob" not in dump
    assert "salut alice" not in dump
    assert e2e.b64(alice.conv_keys[conv_id]) not in dump


def test_one_conversation_per_pair(alice, bob):
    bob.send_friend_request(alice)
    alice.accept_friend(bob)

    conv_id = alice.create_conversation(bob)
    conv_key = e2e.generate_room_key()
    second = alice.post(
        "/api/conversations",
        {
            "username": bob.identity.username,
            "wrapped_key": e2e.wrap_room_key(conv_key, alice.identity.public_key),
            "peer_wrapped_key": e2e.wrap_room_key(conv_key, bob.identity.public_key),
        },
    )
    assert second.status_code == 409  # l'existence d'une conversation se révèle par un 409
    assert alice.conv_list()[0]["id"] == conv_id


def test_conversation_is_reserved_to_friends(alice, bob, make_user):
    dave = make_user("dave")  # ami de personne
    conv_key = e2e.generate_room_key()
    response = alice.post(
        "/api/conversations",
        {
            "username": dave.identity.username,
            "wrapped_key": e2e.wrap_room_key(conv_key, alice.identity.public_key),
            "peer_wrapped_key": e2e.wrap_room_key(conv_key, dave.identity.public_key),
        },
    )
    assert response.status_code == 403


def test_creating_with_an_unknown_user_is_refused(alice):
    conv_key = e2e.generate_room_key()
    response = alice.post(
        "/api/conversations",
        {
            "username": "fantome",
            "wrapped_key": e2e.wrap_room_key(conv_key, alice.identity.public_key),
            "peer_wrapped_key": e2e.wrap_room_key(conv_key, alice.identity.public_key),
        },
    )
    assert response.status_code == 404


def test_non_member_cannot_access_a_conversation(alice, bob, make_user):
    bob.send_friend_request(alice)
    alice.accept_friend(bob)
    carol = make_user("carol")

    conv_id = bob.create_conversation(alice)
    assert carol.get(f"/api/conversations/{conv_id}").status_code == 404
    assert carol.get(f"/api/conversations/{conv_id}/messages").status_code == 404
    payload = e2e.encrypt_message(e2e.generate_room_key(), "intrus", conv_id, carol.user_id)
    assert carol.post(f"/api/conversations/{conv_id}/messages", payload).status_code == 404
    assert carol.conv_list() == []


def test_conversation_messages_and_presence_are_delivered_in_real_time(alice, bob):
    bob.send_friend_request(alice)
    alice.accept_friend(bob)
    conv_id = alice.create_conversation(bob)
    bob.load_conv_key(conv_id)

    with alice.websocket() as alice_socket, bob.websocket():
        # Bob passe en ligne en second : Alice apprend qu'il est là, puis reçoit le message.
        assert alice_socket.receive_json()["type"] == "presence_dm"
        alice.conv_send(conv_id, "en direct")
        event = alice_socket.receive_json()
    assert event["type"] == "dm"
    framed = {
        "room_id": event["message"]["conversation_id"],
        "sender_id": event["message"]["sender_id"],
        "iv": event["message"]["iv"],
        "ciphertext": event["message"]["ciphertext"],
    }
    assert e2e.decrypt_bytes(bob.conv_keys[conv_id], framed) == b"en direct"


def test_conv_presence_is_announced_to_the_partner(alice, bob):
    bob.send_friend_request(alice)
    alice.accept_friend(bob)
    conv_id = alice.create_conversation(bob)

    with bob.websocket() as bob_socket:
        with alice.websocket():
            event = bob_socket.receive_json()
            assert event["type"] == "presence_dm"
            assert event["conversation_id"] == conv_id
            assert event["user_id"] == alice.user_id
            assert event["online"] is True
        event = bob_socket.receive_json()
        assert event["type"] == "presence_dm"
        assert event["online"] is False


def test_conversation_messages_never_reuse_an_iv(alice, bob):
    bob.send_friend_request(alice)
    alice.accept_friend(bob)
    conv_id = alice.create_conversation(bob)

    payload = e2e.encrypt_message(alice.conv_keys[conv_id], "un", conv_id, alice.user_id)
    assert alice.post(f"/api/conversations/{conv_id}/messages", payload).status_code == 201
    replay = {**payload, "ciphertext": e2e.b64(b"\x00" * 64)}  # même IV, contenu différent (redo)
    assert alice.post(f"/api/conversations/{conv_id}/messages", replay).status_code == 409
    assert alice.post(f"/api/conversations/{conv_id}/messages", payload).status_code == 409  # même IV aussi


def test_conversation_history_does_not_leak_room_id(alice, bob):
    bob.send_friend_request(alice)
    alice.accept_friend(bob)
    conv_id = alice.create_conversation(bob)
    alice.conv_send(conv_id, "salut")

    message = alice.get(f"/api/conversations/{conv_id}/messages").json()["messages"][0]
    assert message["conversation_id"] == conv_id
    assert "room_id" not in message
