"""Parcours salons : création, listing, membres, join (404/409), contrôles
d'accès non-membre (403) et enregistrement des clés enveloppées (201/403).
"""

from __future__ import annotations

from tests.helpers.crypto_client import (
    create_room,
    csrf_headers,
    register,
)

B64 = "Y2xhcw=="  # base64 valide ("claw") pour les corps de test


async def test_create_room_sets_owner_as_first_member(client) -> None:
    data = await register(client, "alice_rm", "password123")
    room = await create_room(client, "general", data["csrf_token"])
    assert set(room) == {"id", "name", "owner_id", "created_at"}
    assert room["owner_id"] == data["user"]["id"]

    # Le salon apparaît dans /api/me et /api/rooms.
    me = (await client.get("/api/me")).json()
    assert {"id": room["id"], "name": "general"} in me["rooms"]
    listing = (await client.get("/api/rooms")).json()
    assert room["id"] in {item["id"] for item in listing}

    # Le créateur est le seul membre.
    members = (await client.get(f"/api/rooms/{room['id']}/members")).json()
    assert [member["username"] for member in members] == ["alice_rm"]
    assert set(members[0]) == {"id", "username", "public_key", "online"}


async def test_rooms_listing_contains_all_rooms(client) -> None:
    data = await register(client, "alice_li", "password123")
    first = await create_room(client, "salle-un", data["csrf_token"])
    second = await create_room(client, "salle-deux", data["csrf_token"])
    listing = (await client.get("/api/rooms")).json()
    assert {room["id"] for room in listing} == {first["id"], second["id"]}


async def test_non_member_access_forbidden(make_client, client) -> None:
    data = await register(client, "alice_nm", "password123")
    room = await create_room(client, "prive", data["csrf_token"])
    room_id = room["id"]

    async with make_client() as bob:
        bob_data = await register(bob, "bob_nm", "password123")
        headers = csrf_headers(bob_data["csrf_token"])
        assert (await bob.get(f"/api/rooms/{room_id}/members")).status_code == 403
        assert (await bob.get(f"/api/rooms/{room_id}/messages")).status_code == 403
        post_message = await bob.post(
            f"/api/rooms/{room_id}/messages",
            json={"nonce": B64, "ciphertext": B64},
            headers=headers,
        )
        assert post_message.status_code == 403
        post_keys = await bob.post(
            f"/api/rooms/{room_id}/keys",
            json={"target_user_id": data["user"]["id"], "wrapped_key": B64},
            headers=headers,
        )
        assert post_keys.status_code == 403


async def test_unknown_room_returns_404(client) -> None:
    data = await register(client, "alice_404", "password123")
    headers = csrf_headers(data["csrf_token"])
    assert (await client.get("/api/rooms/inconnue/members")).status_code == 404
    assert (await client.get("/api/rooms/inconnue/messages")).status_code == 404
    assert (await client.post("/api/rooms/inconnue/join", headers=headers)).status_code == 404
    response = await client.post(
        "/api/rooms/inconnue/messages",
        json={"nonce": B64, "ciphertext": B64},
        headers=headers,
    )
    assert response.status_code == 404
    response = await client.post(
        "/api/rooms/inconnue/keys",
        json={"target_user_id": "qui", "wrapped_key": B64},
        headers=headers,
    )
    assert response.status_code == 404


async def test_join_room_and_duplicate_conflict(make_client, client) -> None:
    data = await register(client, "alice_j", "password123")
    room = await create_room(client, "general", data["csrf_token"])
    room_id = room["id"]

    async with make_client() as bob:
        bob_data = await register(bob, "bob_j", "password123")
        headers = csrf_headers(bob_data["csrf_token"])
        joined = await bob.post(f"/api/rooms/{room_id}/join", headers=headers)
        assert joined.status_code == 200
        assert joined.json()["id"] == room_id

        again = await bob.post(f"/api/rooms/{room_id}/join", headers=headers)
        assert again.status_code == 409

        members = (await bob.get(f"/api/rooms/{room_id}/members")).json()
        assert {member["username"] for member in members} == {"alice_j", "bob_j"}

        me = (await bob.get("/api/me")).json()
        assert {"id": room_id, "name": "general"} in me["rooms"]


async def test_owner_joining_own_room_is_conflict(client) -> None:
    data = await register(client, "alice_own", "password123")
    room = await create_room(client, "general", data["csrf_token"])
    response = await client.post(
        f"/api/rooms/{room['id']}/join", headers=csrf_headers(data["csrf_token"])
    )
    assert response.status_code == 409


async def test_store_wrapped_key_for_member(make_client, client) -> None:
    data = await register(client, "alice_k", "password123")
    token = data["csrf_token"]
    room = await create_room(client, "general", token)

    async with make_client() as bob:
        bob_data = await register(bob, "bob_k", "password123")
        await bob.post(
            f"/api/rooms/{room['id']}/join", headers=csrf_headers(bob_data["csrf_token"])
        )

        # Cible : l'auteur lui-même puis un autre membre.
        for target in (data["user"]["id"], bob_data["user"]["id"]):
            response = await client.post(
                f"/api/rooms/{room['id']}/keys",
                json={"target_user_id": target, "wrapped_key": B64},
                headers=csrf_headers(token),
            )
            assert response.status_code == 201
            assert response.json() == {
                "room_id": room["id"],
                "target_user_id": target,
                "stored": True,
            }


async def test_wrapped_key_for_non_member_forbidden(make_client, client) -> None:
    data = await register(client, "alice_nmk", "password123")
    room = await create_room(client, "general", data["csrf_token"])

    async with make_client() as carol:
        carol_data = await register(carol, "carol_nmk", "password123")
        response = await client.post(
            f"/api/rooms/{room['id']}/keys",
            json={"target_user_id": carol_data["user"]["id"], "wrapped_key": B64},
            headers=csrf_headers(data["csrf_token"]),
        )
        assert response.status_code == 403


async def test_room_name_length_validated_via_api(client) -> None:
    data = await register(client, "alice_v", "password123")
    headers = csrf_headers(data["csrf_token"])
    assert (await client.post("/api/rooms", json={"name": ""}, headers=headers)).status_code == 422
    too_long = await client.post("/api/rooms", json={"name": "x" * 65}, headers=headers)
    assert too_long.status_code == 422
