async def test_salon_has_default_channel(auth_headers, salon_id):
    response = await auth_headers.get(f"/salons/{salon_id}/channels")
    assert response.status_code == 200
    channels = response.json()
    assert len(channels) == 1
    assert channels[0]["name"] == "général"


async def test_create_channel(auth_headers, salon_id):
    response = await auth_headers.post(f"/salons/{salon_id}/channels", json={"name": "annonces"})
    assert response.status_code == 201
    assert response.json()["name"] == "annonces"

    channels = (await auth_headers.get(f"/salons/{salon_id}/channels")).json()
    assert [c["name"] for c in channels] == ["général", "annonces"]


async def test_duplicate_channel_rejected(auth_headers, salon_id):
    await auth_headers.post(f"/salons/{salon_id}/channels", json={"name": "annonces"})
    response = await auth_headers.post(f"/salons/{salon_id}/channels", json={"name": "annonces"})
    assert response.status_code == 409


async def test_channel_name_validation(auth_headers, salon_id):
    response = await auth_headers.post(f"/salons/{salon_id}/channels", json={"name": "Nom Avec Majuscules"})
    assert response.status_code == 422


async def test_only_owner_creates_channel(auth_headers, salon_id, csrf_client, second_user):
    # Bob rejoint le salon...
    bob = (await auth_headers.get(f"/auth/users/{second_user['payload']['username']}/public-key")).json()
    await auth_headers.post(
        f"/salons/{salon_id}/members",
        json={"user_id": bob["id"], "encrypted_salon_key": "key-for-bob"},
    )

    # ... mais ne peut pas créer de canal.
    csrf_client.headers["Authorization"] = f"Bearer {second_user['tokens']['access_token']}"
    response = await csrf_client.post(f"/salons/{salon_id}/channels", json={"name": "pirate"})
    assert response.status_code == 403


async def test_non_member_cannot_list_channels(auth_headers, salon_id, csrf_client, second_user):
    csrf_client.headers["Authorization"] = f"Bearer {second_user['tokens']['access_token']}"
    response = await csrf_client.get(f"/salons/{salon_id}/channels")
    assert response.status_code == 403


async def test_remove_member_rotates_key(auth_headers, salon_id, second_user):
    bob = (await auth_headers.get(f"/auth/users/{second_user['payload']['username']}/public-key")).json()
    await auth_headers.post(
        f"/salons/{salon_id}/members",
        json={"user_id": bob["id"], "encrypted_salon_key": "key-for-bob"},
    )

    salon = (await auth_headers.get(f"/salons/{salon_id}")).json()
    assert len(salon["members"]) == 2
    owner_id = salon["owner_id"]
    assert salon["key_version"] == 1

    response = await auth_headers.request(
        "DELETE",
        f"/salons/{salon_id}/members/{bob['id']}",
        json={"rekey": [{"user_id": owner_id, "encrypted_salon_key": "rotated-key"}]},
    )
    assert response.status_code == 200

    salon = (await auth_headers.get(f"/salons/{salon_id}")).json()
    assert len(salon["members"]) == 1
    assert salon["members"][0]["encrypted_salon_key"] == "rotated-key"
    # La version de clé augmente : les anciens messages restent lisibles,
    # les nouveaux le sont uniquement avec la clé régénérée.
    assert salon["key_version"] == 2


async def test_removed_member_loses_access(auth_headers, salon_id, csrf_client, second_user):
    bob = (await auth_headers.get(f"/auth/users/{second_user['payload']['username']}/public-key")).json()
    await auth_headers.post(
        f"/salons/{salon_id}/members",
        json={"user_id": bob["id"], "encrypted_salon_key": "key-for-bob"},
    )
    await auth_headers.request(
        "DELETE",
        f"/salons/{salon_id}/members/{bob['id']}",
        json={"rekey": []},
    )

    csrf_client.headers["Authorization"] = f"Bearer {second_user['tokens']['access_token']}"
    response = await csrf_client.get(f"/salons/{salon_id}/messages")
    assert response.status_code == 403


async def test_owner_cannot_be_removed(auth_headers, salon_id):
    salon = (await auth_headers.get(f"/salons/{salon_id}")).json()
    response = await auth_headers.request(
        "DELETE",
        f"/salons/{salon_id}/members/{salon['owner_id']}",
        json={"rekey": []},
    )
    assert response.status_code == 400
