"""Grades dans les salons : chef (propriétaire), sous-chef, membre."""


def test_creator_is_owner_and_others_join_as_members(alice, bob):
    room_id = alice.create_room()
    alice.add_member(room_id, bob)

    assert alice.get(f"/api/rooms/{room_id}").json()["roles"] == {
        alice.user_id: "owner",
        bob.user_id: "member",
    }


def test_owner_can_promote_and_demote_a_sub_chef(alice, bob, make_user):
    carol = make_user("carol")
    room_id = alice.create_room()
    alice.add_member(room_id, bob)
    bob.load_room_key(room_id)

    assert alice.set_role(room_id, bob, "co").status_code == 204
    roles = alice.get(f"/api/rooms/{room_id}").json()["roles"]
    assert roles[bob.user_id] == "co"

    # Un sous-chef peut ajouter des membres comme le chef (mais pas les rétrograder).
    assert bob.add_member(room_id, carol).status_code == 201
    assert bob.set_role(room_id, carol, "co").status_code == 403

    assert alice.set_role(room_id, bob, "member").status_code == 204
    roles = alice.get(f"/api/rooms/{room_id}").json()["roles"]
    assert roles[bob.user_id] == "member"
    assert bob.add_member(room_id, carol).status_code == 403  # redevenu membre, il ne peut plus inviter


def test_only_the_owner_can_change_roles(alice, bob, make_user):
    carol = make_user("carol")
    room_id = alice.create_room()
    alice.add_member(room_id, bob)
    bob.load_room_key(room_id)

    assert bob.set_role(room_id, carol, "co").status_code == 403
    assert bob.set_role(room_id, bob, "co").status_code == 403


def test_only_owner_co_member_grades_are_acceptable(alice, bob):
    room_id = alice.create_room()
    alice.add_member(room_id, bob)
    bob.load_room_key(room_id)

    for forbidden in ["owner", "chef", "admin", "*"]:
        response = alice.post(
            f"/api/rooms/{room_id}/roles", {"username": bob.identity.username, "role": forbidden}
        )
        assert response.status_code == 422


def test_owner_cannot_change_its_own_grade(alice, bob):
    room_id = alice.create_room()
    alice.add_member(room_id, bob)
    assert alice.set_role(room_id, alice, "co").status_code == 400


def test_roles_only_apply_to_members_of_the_room(alice, bob, make_user):
    dave = make_user("dave")  # n'est pas membre du salon
    room_id = alice.create_room()
    assert alice.set_role(room_id, dave, "co").status_code == 404


def test_role_change_is_announced_to_all_members(alice, bob):
    room_id = alice.create_room()
    alice.add_member(room_id, bob)

    with bob.websocket() as bob_socket:
        assert alice.set_role(room_id, bob, "co").status_code == 204
        event = bob_socket.receive_json()
    assert event["type"] == "role_changed"
    assert event["room_id"] == room_id
    assert event["user"]["username"] == "bob"
    assert event["role"] == "co"
