async def test_create_salon(auth_headers):
    response = await auth_headers.post(
        "/salons",
        json={
            "name": "General",
            "encrypted_salon_key": "base64_encrypted_key_here",
        },
    )
    assert response.status_code == 201
    data = response.json()
    assert data["name"] == "General"
    assert len(data["members"]) == 1


async def test_list_salons(auth_headers):
    await auth_headers.post(
        "/salons",
        json={
            "name": "General",
            "encrypted_salon_key": "base64_encrypted_key_here",
        },
    )
    response = await auth_headers.get("/salons")
    assert response.status_code == 200
    data = response.json()
    assert len(data) == 1
    assert data[0]["name"] == "General"


async def test_get_salon(auth_headers):
    create_resp = await auth_headers.post(
        "/salons",
        json={
            "name": "General",
            "encrypted_salon_key": "base64_encrypted_key_here",
        },
    )
    salon_id = create_resp.json()["id"]
    response = await auth_headers.get(f"/salons/{salon_id}")
    assert response.status_code == 200
    assert response.json()["name"] == "General"


async def test_add_member(auth_headers, second_user):
    # Bob est créé par la fixture ; son identifiant se lit via sa clé publique.
    bob_id = (await auth_headers.get(f"/auth/users/{second_user['payload']['username']}/public-key")).json()["id"]

    # Alice creates a salon
    create_resp = await auth_headers.post(
        "/salons",
        json={
            "name": "Private",
            "encrypted_salon_key": "alice_encrypted_key",
        },
    )
    salon_id = create_resp.json()["id"]

    # Alice adds bob
    response = await auth_headers.post(
        f"/salons/{salon_id}/members",
        json={
            "user_id": bob_id,
            "encrypted_salon_key": "bob_encrypted_key",
        },
    )
    assert response.status_code == 201

    # Verify salon has 2 members
    salon_resp = await auth_headers.get(f"/salons/{salon_id}")
    assert len(salon_resp.json()["members"]) == 2


async def test_create_salon_unauthenticated(csrf_client):
    response = await csrf_client.post(
        "/salons",
        json={
            "name": "Nope",
            "encrypted_salon_key": "key",
        },
    )
    assert response.status_code == 401
