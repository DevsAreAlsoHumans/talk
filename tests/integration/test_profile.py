"""Profil utilisateur et avatars chiffrés : métadonnées visibles, images E2E par salon."""

from tests.helpers import e2e


def test_me_returns_the_profile_details(alice):
    body = alice.get("/api/me").json()
    assert body["username"] == alice.identity.username
    assert body["display_name"] == alice.identity.username  # par défaut, le surnom est le pseudo
    assert body["bio"] == ""


def test_profile_is_updated_and_visible_to_other_members(alice, bob):
    room_id = alice.create_room()
    alice.add_member(room_id, bob)

    response = alice.update_profile("Alicia", "Maths & crypto")
    assert response.status_code == 200
    assert response.json()["display_name"] == "Alicia"
    assert response.json()["bio"] == "Maths & crypto"

    detail = bob.get(f"/api/rooms/{room_id}").json()
    members = {member["username"]: member for member in detail["members"]}
    assert members["alice"]["display_name"] == "Alicia"
    assert members["alice"]["bio"] == "Maths & crypto"
    assert members["bob"]["display_name"] == "bob"


def test_profile_validation(alice, bob):
    room_id = alice.create_room()
    alice.add_member(room_id, bob)
    assert alice.update_profile("", "bio").status_code == 200
    assert alice.update_profile("ok", "").status_code == 200
    for payload in [{"display_name": "x" * 33, "bio": ""}, {"display_name": "ok", "bio": "y" * 201}]:
        response = alice.put("/api/me/profile", payload)
        assert response.status_code == 422


def test_theme_preference_is_per_user_and_persisted(alice, bob):
    assert alice.get("/api/me").json()["theme"] == "dark"

    response = alice.put("/api/me/theme", {"theme": "light"})
    assert response.status_code == 200
    assert response.json()["theme"] == "light"
    assert alice.get("/api/me").json()["theme"] == "light"

    # Le thème est une préférence personnelle : les autres comptes et les membres de salon n'y ont pas accès.
    assert bob.get("/api/me").json()["theme"] == "dark"
    detail = alice.create_room()
    assert "theme" not in alice.get(f"/api/rooms/{detail}").json()["members"][0]

    for payload in [{"theme": "blue"}, {}, {"theme": "LIGHT"}]:
        assert alice.put("/api/me/theme", payload).status_code == 422


def test_avatar_is_stored_encrypted_inside_the_room_only(alice, bob):
    room_id = alice.create_room()
    alice.add_member(room_id, bob)
    bob.load_room_key(room_id)
    avatar = b"\xff\xd8\xff\xe0" + bytes(64)

    assert alice.set_avatar(room_id, avatar).status_code == 204

    detail = bob.get(f"/api/rooms/{room_id}").json()
    envelope = detail["avatars"][alice.user_id]
    decrypted = e2e.decrypt_bytes(
        bob.room_keys[room_id], {**envelope, "room_id": room_id, "sender_id": alice.user_id}
    )
    assert decrypted == avatar
    assert e2e.b64(avatar) not in str(detail)  # aucun avatar en clair dans la réponse

    room = alice.load_room_key(room_id)
    assert e2e.decrypt_bytes(room, {**envelope, "room_id": room_id, "sender_id": alice.user_id}) == avatar


def test_avatar_iv_cannot_be_reused_for_a_message(alice):
    room_id = alice.create_room()
    payload = e2e.encrypt_bytes(alice.room_keys[room_id], b"\x00" * 32, room_id, alice.user_id)
    response = alice.post(f"/api/rooms/{room_id}/messages", {**payload, "kind": "image", "mime": "image/png"})
    assert response.status_code == 201
    assert alice.put(f"/api/rooms/{room_id}/avatar", payload).status_code == 409


def test_avatar_is_per_room_and_stays_invisible_to_non_members(alice, bob, make_user):
    carol = make_user("carol")
    block_a = alice.create_room("bloc A")
    block_b = alice.create_room("bloc B")
    alice.add_member(block_b, carol)

    avatar_a = bytes([1]) * 32
    avatar_b = bytes([2]) * 32
    assert alice.set_avatar(block_a, avatar_a).status_code == 204
    assert alice.set_avatar(block_b, avatar_b).status_code == 204

    # Carol ne voit que l'avatar du salon qu'elle partage.
    detail_b = carol.get(f"/api/rooms/{block_b}").json()
    assert alice.user_id in detail_b["avatars"]
    assert carol.get(f"/api/rooms/{block_a}").status_code == 404
    assert alice.get(f"/api/rooms/{block_a}").json()["avatars"] != detail_b["avatars"]


def test_avatar_validation(alice):
    room_id = alice.create_room()
    too_small = e2e.encrypt_bytes(alice.room_keys[room_id], b"x", room_id, alice.user_id)
    assert alice.put(f"/api/rooms/{room_id}/avatar", too_small).status_code == 422
    bad_iv = {"iv": e2e.b64(b"x" * 8), "ciphertext": e2e.b64(b"y" * 20)}
    assert alice.put(f"/api/rooms/{room_id}/avatar", bad_iv).status_code == 422
