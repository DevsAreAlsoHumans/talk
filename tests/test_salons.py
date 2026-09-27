from fastapi.testclient import TestClient

def _create_salon(client: TestClient, headers: dict, name: str = "mon-salon") -> dict:
    response = client.post("/salons", json={"name": name}, headers=headers)
    assert response.status_code == 201, response.text
    return response.json()


def _default_channel(client: TestClient, salon_id: str) -> dict:
    channels = client.get(f"/salons/{salon_id}/channels").json()
    assert len(channels) == 1
    return channels[0]


def test_create_salon_becomes_owner(client: TestClient, registered) -> None:
    salon = _create_salon(client, registered)
    assert salon["role"] == "owner"
    assert salon["member_count"] == 1
    assert _default_channel(client, salon["id"])["name"] == "general"


def test_create_salon_requires_csrf(client: TestClient) -> None:
    response = client.post("/salons", json={"name": "sans-jeton"})
    assert response.status_code == 403


def test_create_salon_requires_authentication(client: TestClient, csrf_headers) -> None:
    assert client.post("/salons", json={"name": "anonyme"}, headers=csrf_headers).status_code == 401


def test_salon_name_is_validated(client: TestClient, registered) -> None:
    assert client.post("/salons", json={"name": "x"}, headers=registered).status_code == 422
    assert client.post("/salons", json={"name": "<b>x</b>"}, headers=registered).status_code == 422


def test_list_salons_is_isolated_per_user(client: TestClient, registered, other_account) -> None:
    _create_salon(client, registered, "salon-propre")
    assert client.get("/salons").json()[0]["name"] == "salon-propre"
    assert other_account["client"].get("/salons").json() == []


def test_non_member_gets_404(client: TestClient, registered, other_account) -> None:
    salon_id = _create_salon(client, registered)["id"]
    response = other_account["client"].get(f"/salons/{salon_id}")
    assert response.status_code == 404


def test_member_can_be_added_and_removed(client: TestClient, registered, other_account) -> None:
    salon_id = _create_salon(client, registered)["id"]
    add = client.post(
        f"/salons/{salon_id}/members", json={"username": "invitee"}, headers=registered
    )
    assert add.status_code == 200

    guest = other_account["client"]
    assert guest.get(f"/salons/{salon_id}").json()["role"] == "member"
    members = client.get(f"/salons/{salon_id}/members").json()["members"]
    assert {member["username"] for member in members} == {"augustin", "invitee"}

    remove = client.request(
        "DELETE", f"/salons/{salon_id}/members/{other_account['user']['id']}", headers=registered
    )
    assert remove.status_code == 200
    assert guest.get(f"/salons/{salon_id}").status_code == 404


def test_member_cannot_add_members(client: TestClient, registered, other_account) -> None:
    salon_id = _create_salon(client, registered)["id"]
    guest = other_account["client"]
    guest.post(
        f"/salons/{salon_id}/members",
        json={"username": "invitee"},
        headers=other_account["headers"],
    )
    forbidden = guest.post(
        f"/salons/{salon_id}/members",
        json={"username": "augustin"},
        headers=other_account["headers"],
    )
    assert forbidden.status_code == 403


def test_owner_cannot_be_removed(client: TestClient, registered, other_account) -> None:
    salon_id = _create_salon(client, registered)["id"]
    client.post(f"/salons/{salon_id}/members", json={"username": "invitee"}, headers=registered)
    unknown = client.request(
        "DELETE", f"/salons/{salon_id}/members/inconnu", headers=registered
    )
    assert unknown.status_code == 404
    owner_id = next(
        member["id"]
        for member in client.get(f"/salons/{salon_id}/members").json()["members"]
        if member["role"] == "owner"
    )
    conflict = client.request(
        "DELETE", f"/salons/{salon_id}/members/{owner_id}", headers=registered
    )
    assert conflict.status_code == 409


def test_only_owner_can_delete_salon(client: TestClient, registered, other_account) -> None:
    salon_id = _create_salon(client, registered)["id"]
    guest = other_account["client"]
    guest.post(
        f"/salons/{salon_id}/members",
        json={"username": "invitee"},
        headers=other_account["headers"],
    )
    forbidden = guest.request("DELETE", f"/salons/{salon_id}", headers=other_account["headers"])
    assert forbidden.status_code == 403
    assert client.request("DELETE", f"/salons/{salon_id}", headers=registered).status_code == 200
    assert client.get("/salons").json() == []


def test_rename_salon_requires_moderator(client: TestClient, registered, other_account) -> None:
    salon_id = _create_salon(client, registered)["id"]
    guest = other_account["client"]
    guest.post(
        f"/salons/{salon_id}/members",
        json={"username": "invitee"},
        headers=other_account["headers"],
    )
    forbidden = guest.patch(
        f"/salons/{salon_id}", json={"name": "pique"}, headers=other_account["headers"]
    )
    assert forbidden.status_code == 403
    renamed = client.patch(
        f"/salons/{salon_id}", json={"name": "nouveau-nom"}, headers=registered
    )
    assert renamed.status_code == 200
    assert client.get(f"/salons/{salon_id}").json()["name"] == "nouveau-nom"


def test_create_channel_and_conflict(client: TestClient, registered) -> None:
    salon_id = _create_salon(client, registered)["id"]
    created = client.post(
        f"/salons/{salon_id}/channels", json={"name": "dev"}, headers=registered
    )
    assert created.status_code == 201
    assert created.json()["kind"] == "text"
    duplicate = client.post(
        f"/salons/{salon_id}/channels", json={"name": "dev"}, headers=registered
    )
    assert duplicate.status_code == 409


def test_channel_name_is_validated(client: TestClient, registered) -> None:
    salon_id = _create_salon(client, registered)["id"]
    assert client.post(
        f"/salons/{salon_id}/channels", json={"name": "A"}, headers=registered
    ).status_code == 422
    assert client.post(
        f"/salons/{salon_id}/channels", json={"name": "salut; drop"}, headers=registered
    ).status_code == 422


def test_private_channel_is_hidden_from_non_members(
    client: TestClient, registered, other_account
) -> None:
    salon_id = _create_salon(client, registered)["id"]
    private = client.post(
        f"/salons/{salon_id}/channels",
        json={"name": "staff", "kind": "private"},
        headers=registered,
    ).json()
    guest = other_account["client"]
    guest.post(
        f"/salons/{salon_id}/members",
        json={"username": "invitee"},
        headers=other_account["headers"],
    )

    listed = [item["name"] for item in guest.get(f"/salons/{salon_id}/channels").json()]
    assert "staff" not in listed
    assert guest.get(f"/channels/{private['id']}").status_code == 404

    grant = guest.post(
        f"/channels/{private['id']}/members",
        json={"username": "invitee"},
        headers=other_account["headers"],
    )
    assert grant.status_code == 403
    client.post(
        f"/channels/{private['id']}/members",
        json={"username": "invitee"},
        headers=registered,
    )
    assert guest.get(f"/channels/{private['id']}").status_code == 200
    access = client.get(f"/channels/{private['id']}/members").json()["members"]
    assert {member["username"] for member in access} == {"augustin", "invitee"}


def test_delete_channel(client: TestClient, registered) -> None:
    salon_id = _create_salon(client, registered)["id"]
    extra = client.post(
        f"/salons/{salon_id}/channels", json={"name": "temporaire"}, headers=registered
    ).json()
    deleted = client.request("DELETE", f"/channels/{extra['id']}", headers=registered)
    assert deleted.status_code == 200
    last = _default_channel(client, salon_id)["id"]
    assert client.request("DELETE", f"/channels/{last}", headers=registered).status_code == 409


def test_salon_payload_never_leaks_hashes(client: TestClient, registered) -> None:
    salon_id = _create_salon(client, registered)["id"]
    body = client.get("/salons").text + client.get(f"/salons/{salon_id}/members").text
    assert "password" not in body
    assert "scrypt$" not in body
