"""Salons : création, liste, détail, ajout de membres, contrôle d'accès."""

from tests.helpers import e2e


def test_create_and_list_rooms(alice):
    room_id = alice.create_room("général")
    rooms = alice.get("/api/rooms").json()
    assert [(room["id"], room["name"], room["member_count"]) for room in rooms] == [(room_id, "général", 1)]


def test_room_detail_returns_members_and_my_wrapped_key(alice):
    room_id = alice.create_room()
    detail = alice.get(f"/api/rooms/{room_id}").json()
    assert detail["owner_id"] == alice.user_id
    assert [member["username"] for member in detail["members"]] == ["alice"]
    assert e2e.unwrap_room_key(detail["wrapped_key"], alice.identity.private_key) == alice.room_keys[room_id]


def test_owner_adds_member_who_can_then_unwrap_the_room_key(alice, bob):
    room_id = alice.create_room()
    assert alice.add_member(room_id, bob).status_code == 201

    assert [room["id"] for room in bob.get("/api/rooms").json()] == [room_id]
    assert bob.load_room_key(room_id) == alice.room_keys[room_id]
    members = bob.get(f"/api/rooms/{room_id}").json()["members"]
    assert [member["username"] for member in members] == ["alice", "bob"]


def test_adding_the_same_member_twice_is_refused(alice, bob):
    room_id = alice.create_room()
    assert alice.add_member(room_id, bob).status_code == 201
    assert alice.add_member(room_id, bob).status_code == 409


def test_only_the_owner_can_add_members(alice, bob, make_user):
    carol = make_user("carol")
    room_id = alice.create_room()
    alice.add_member(room_id, bob)
    bob.load_room_key(room_id)
    assert bob.add_member(room_id, carol).status_code == 403


def test_adding_an_unknown_user_is_refused(alice):
    room_id = alice.create_room()
    ghost = e2e.Identity.create("fantome")
    wrapped = e2e.wrap_room_key(alice.room_keys[room_id], ghost.public_key)
    response = alice.post(f"/api/rooms/{room_id}/members", {"username": "fantome", "wrapped_key": wrapped})
    assert response.status_code == 404


def test_non_member_cannot_see_or_touch_a_room(alice, bob):
    room_id = alice.create_room()
    assert bob.get(f"/api/rooms/{room_id}").status_code == 404
    assert bob.get(f"/api/rooms/{room_id}/messages").status_code == 404
    valid_payload = e2e.encrypt_message(e2e.generate_room_key(), "intrus", room_id, bob.user_id)
    assert bob.post(f"/api/rooms/{room_id}/messages", valid_payload).status_code == 404
    bob.room_keys[room_id] = e2e.generate_room_key()
    assert bob.add_member(room_id, bob).status_code == 404
    assert bob.get("/api/rooms").json() == []


def test_unknown_room_and_non_member_get_the_same_answer(alice, bob):
    room_id = alice.create_room()
    unknown = "00000000-0000-4000-8000-000000000000"
    assert bob.get(f"/api/rooms/{room_id}").json() == bob.get(f"/api/rooms/{unknown}").json()


def test_malformed_room_id_is_rejected_by_validation(alice):
    for bad in ["nope", "1", "*", "..%2F..%2Fetc"]:
        assert alice.get(f"/api/rooms/{bad}").status_code in (404, 422)


def test_user_lookup_returns_only_public_data(alice, bob):
    response = alice.get("/api/users/bob")
    assert response.status_code == 200
    assert set(response.json()) == {"id", "username", "public_key"}
    assert alice.get("/api/users/personne").status_code == 404
    assert alice.get("/api/users/a:b*").status_code == 422
