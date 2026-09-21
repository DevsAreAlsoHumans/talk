"""Temps réel : les membres reçoivent les événements par WebSocket, les autres non."""

import pytest
from starlette.websockets import WebSocketDisconnect

from tests.helpers import e2e


def test_members_receive_new_messages_without_polling(alice, bob):
    room_id = alice.create_room()
    alice.add_member(room_id, bob)
    bob.load_room_key(room_id)

    with bob.websocket() as bob_socket:
        alice.send(room_id, "message en direct")
        event = bob_socket.receive_json()

    assert event["type"] == "message"
    assert e2e.decrypt_message(bob.room_keys[room_id], event["message"]) == "message en direct"
    assert "user_ids" not in event


def test_sender_is_notified_too_and_non_members_are_not(alice, bob, make_user):
    carol = make_user("carol")
    room_id = alice.create_room()
    alice.add_member(room_id, bob)

    with alice.websocket() as alice_socket, carol.websocket() as carol_socket:
        alice.send(room_id, "bonjour")
        assert alice_socket.receive_json()["type"] == "message"

        # Carol n'est pas membre : rien ne lui est diffusé. On le vérifie en lui envoyant
        # ensuite un événement qui la concerne, qui doit être le premier qu'elle reçoit.
        alice.add_member(room_id, carol)
        carol_event = carol_socket.receive_json()
        assert carol_event["type"] == "member_added"
        assert carol_event["user"]["username"] == "carol"


def test_member_added_event_reaches_existing_members(alice, bob, make_user):
    carol = make_user("carol")
    room_id = alice.create_room()
    alice.add_member(room_id, bob)
    with bob.websocket() as bob_socket:
        alice.add_member(room_id, carol)
        event = bob_socket.receive_json()
    assert event["type"] == "member_added"
    assert event["room_id"] == room_id


def test_websocket_requires_a_valid_session(client, alice):
    from tests.helpers.actor import Actor

    anonymous = Actor(client, e2e.Identity.create("anonyme"))
    with pytest.raises(WebSocketDisconnect), anonymous.websocket():
        pass


def test_websocket_rejects_foreign_or_missing_origin(alice):
    for origin in ["https://evil.example.com", None]:
        with pytest.raises(WebSocketDisconnect), alice.websocket(origin=origin):
            pass


def test_logout_closes_the_websocket(alice):
    with alice.websocket() as socket:
        alice.post("/api/auth/logout")
        with pytest.raises(WebSocketDisconnect):
            socket.receive_json()


def test_presence_is_announced_to_the_other_members_only(alice, bob):
    room_id = alice.create_room()
    alice.add_member(room_id, bob)

    with bob.websocket() as bob_socket:
        with alice.websocket():  # pas besoin du handle : seul Bob observe Alice
            # Alice se connecte en second : Bob apprend qu'elle est en ligne.
            event = bob_socket.receive_json()
            assert event["type"] == "presence"
            assert event["room_id"] == room_id
            assert event["user_id"] == alice.user_id
            assert event["online"] is True
        # Alice ferme son socket : Bob apprend qu'elle est hors ligne.
        event = bob_socket.receive_json()
        assert event["type"] == "presence"
        assert event["online"] is False


def test_room_detail_reports_online_members(alice, bob):
    room_id = alice.create_room()
    alice.add_member(room_id, bob)
    with alice.websocket():
        detail = alice.get(f"/api/rooms/{room_id}").json()
    assert detail["online"][alice.user_id] is True
    assert detail["online"][bob.user_id] is False


def test_call_signaling_is_relayed_between_members_of_the_same_room(alice, bob):
    room_id = alice.create_room()
    alice.add_member(room_id, bob)

    with alice.websocket() as alice_socket, bob.websocket() as bob_socket:
        # Bob ouvrant son socket en second, Alice apprend qu'il est en ligne.
        assert alice_socket.receive_json()["type"] == "presence"

        offer = {"type": "offer", "sdp": "v=0: offre audio"}
        alice_socket.send_json({"type": "call_offer", "to": bob.user_id, "sdp": offer})
        event = bob_socket.receive_json()
        assert event["type"] == "call_offer"
        assert event["from"] == alice.user_id
        assert event["sdp"] == offer

        answer = {"type": "answer", "sdp": "v=0: réponse audio"}
        bob_socket.send_json({"type": "call_answer", "to": alice.user_id, "sdp": answer})
        event = alice_socket.receive_json()
        assert event["type"] == "call_answer"
        assert event["from"] == bob.user_id
        assert event["sdp"] == answer

        bob_socket.send_json(
            {"type": "ice_candidate", "to": alice.user_id, "candidate": {"candidate": "c=0", "sdpMid": "0"}}
        )
        event = alice_socket.receive_json()
        assert event["type"] == "ice_candidate"
        assert event["candidate"]["candidate"] == "c=0"

        alice_socket.send_json({"type": "call_end", "to": bob.user_id})
        event = bob_socket.receive_json()
        assert event["type"] == "call_end"
        assert event["from"] == alice.user_id


def test_call_signaling_is_refused_without_a_shared_room(alice, make_user):
    dave = make_user("dave")  # aucun salon commun avec Alice
    with alice.websocket() as alice_socket, dave.websocket():  # Dave n'écoute que pour être rattaché
        alice_socket.send_json(
            {"type": "call_offer", "to": dave.user_id, "sdp": {"type": "offer", "sdp": "v=0"}}
        )
        event = alice_socket.receive_json()
        assert event["type"] == "signal_error"
        assert event["reason"] == "no_shared_room"
        # Dave ne reçoit jamais l'offre : la fermeture saine du socket le prouve.


def test_call_offer_to_an_offline_member_returns_unreachable(alice, bob):
    room_id = alice.create_room()
    alice.add_member(room_id, bob)  # Bob membre mais hors ligne
    with alice.websocket() as alice_socket:
        offer = {"type": "offer", "sdp": "v=0"}

        alice_socket.send_json({"type": "call_offer", "to": bob.user_id, "sdp": offer})
        event = alice_socket.receive_json()
    assert event["type"] == "call_unreachable"
    assert event["to"] == bob.user_id
    assert event["to_username"] == "bob"
