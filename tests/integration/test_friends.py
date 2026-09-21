"""Amis : demande, acceptation, refus, retrait, notifications en temps réel."""


def test_friend_request_and_accept_flow(alice, bob):
    assert bob.send_friend_request(alice).status_code == 201
    assert [user["username"] for user in alice.friend_requests()] == ["bob"]
    assert alice.friend_list() == []
    assert bob.friend_list() == []

    assert alice.accept_friend(bob).status_code == 200
    assert [user["username"] for user in alice.friend_list()] == ["bob"]
    assert [user["username"] for user in bob.friend_list()] == ["alice"]
    assert alice.friend_requests() == []


def test_duplicate_friend_request_is_refused(alice, bob):
    assert bob.send_friend_request(alice).status_code == 201
    assert bob.send_friend_request(alice).status_code == 409
    assert alice.send_friend_request(bob).status_code == 409  # déjà une demande en cours (dans l'autre sens)


def test_already_friends_cannot_request_again(alice, bob):
    bob.send_friend_request(alice)
    alice.accept_friend(bob)
    assert alice.send_friend_request(bob).status_code == 409


def test_decline_removes_the_pending_request(alice, bob):
    assert bob.send_friend_request(alice).status_code == 201
    assert alice.decline_friend(bob).status_code == 204
    assert alice.friend_requests() == []
    assert alice.friend_list() == []
    assert bob.friend_list() == []
    assert bob.send_friend_request(alice).status_code == 201  # on peut redemander ensuite


def test_remove_friend_cuts_the_link_both_ways(alice, bob):
    bob.send_friend_request(alice)
    alice.accept_friend(bob)
    assert alice.remove_friend(bob).status_code == 204
    assert alice.friend_list() == []
    assert bob.friend_list() == []
    assert alice.remove_friend(bob).status_code == 404  # plus rien à retirer


def test_cannot_befriend_yourself_or_a_ghost(alice, bob):
    assert alice.send_friend_request(alice).status_code == 400
    response = alice.post("/api/friends/requests", {"username": "fantome"})
    assert response.status_code == 404


def test_friend_request_arrives_in_real_time(alice, bob):
    with bob.websocket() as bob_socket:
        assert alice.send_friend_request(bob).status_code == 201
        event = bob_socket.receive_json()
    assert event["type"] == "friend_request"
    assert event["from"]["username"] == "alice"


def test_friend_accepted_notifies_the_requester(alice, bob):
    bob.send_friend_request(alice)
    with alice.websocket() as alice_socket:
        alice.accept_friend(bob)
        event = alice_socket.receive_json()
    assert event["type"] == "friend_accepted"
    assert event["user"]["username"] == "bob"


def test_friend_declined_notifies_the_requester(alice, bob):
    bob.send_friend_request(alice)
    with bob.websocket() as bob_socket:
        alice.decline_friend(bob)
        event = bob_socket.receive_json()
    assert event["type"] == "friend_declined"
    assert event["user"]["username"] == "alice"


def test_sending_a_request_does_not_leak_the_targets_secrets(alice, bob):
    response = alice.send_friend_request(bob)
    body = response.json()
    assert set(body) == {"id", "username", "public_key", "display_name", "bio"}
