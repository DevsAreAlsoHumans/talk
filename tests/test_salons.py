from fastapi.testclient import TestClient

from tests.conftest import CIPHERTEXT, add_member, demote


def test_create_salon_becomes_owner(client: TestClient, registered) -> None:
    response = client.post("/salons", json={"name": "mon-salon"}, headers=registered)
    assert response.status_code == 201
    assert response.json()["role"] == "owner"
    channels = client.get(f"/salons/{response.json()['id']}/channels").json()
    assert [item["name"] for item in channels] == ["general"]


def test_create_salon_requires_csrf(client: TestClient) -> None:
    assert client.post("/salons", json={"name": "sans-jeton"}).status_code == 403


def test_create_salon_requires_authentication(client: TestClient, csrf_headers) -> None:
    anonymous = client.post("/salons", json={"name": "anonyme"}, headers=csrf_headers)
    assert anonymous.status_code == 401


def test_salon_name_is_validated(client: TestClient, registered) -> None:
    assert client.post("/salons", json={"name": "x"}, headers=registered).status_code == 422
    assert client.post("/salons", json={"name": "<b>x</b>"}, headers=registered).status_code == 422


def test_list_salons_is_isolated_per_user(client: TestClient, registered, other_account) -> None:
    client.post("/salons", json={"name": "salon-propre"}, headers=registered)
    assert client.get("/salons").json()[0]["name"] == "salon-propre"
    assert other_account["client"].get("/salons").json() == []


def test_non_member_gets_404(client: TestClient, salon, other_account) -> None:
    assert other_account["client"].get(f"/salons/{salon['id']}").status_code == 404


def test_member_can_be_added_and_removed(
    client: TestClient, salon, registered, other_account
) -> None:
    guest = other_account["client"]
    add_member(client, salon["id"], registered)
    assert guest.get(f"/salons/{salon['id']}").json()["role"] == "moderator"
    # Le proprietaire peut retrograder un invite en membre simple.
    demoted = client.patch(
        f"/salons/{salon['id']}/members/{other_account['user']['id']}",
        json={"role": "member"},
        headers=registered,
    )
    assert demoted.status_code == 200
    assert guest.get(f"/salons/{salon['id']}").json()["role"] == "member"
    members = client.get(f"/salons/{salon['id']}/members").json()["members"]
    assert {member["username"] for member in members} == {"augustin", "invitee"}

    removed = client.request(
        "DELETE",
        f"/salons/{salon['id']}/members/{other_account['user']['id']}",
        headers=registered,
    )
    assert removed.status_code == 200
    assert guest.get(f"/salons/{salon['id']}").status_code == 404


def test_member_cannot_add_members(client: TestClient, salon, registered, other_account) -> None:
    add_member(client, salon["id"], registered)
    demote(client, salon, registered, other_account)
    forbidden = other_account["client"].post(
        f"/salons/{salon['id']}/members",
        json={"username": "augustin"},
        headers=other_account["headers"],
    )
    assert forbidden.status_code == 403


def test_owner_can_change_a_member_role(
    client: TestClient, salon, registered, other_account
) -> None:
    guest = other_account["client"]
    add_member(client, salon["id"], registered)
    promoted = client.patch(
        f"/salons/{salon['id']}/members/{other_account['user']['id']}",
        json={"role": "moderator"},
        headers=registered,
    )
    assert promoted.status_code == 200
    assert promoted.json()["role"] == "moderator"
    demoted = client.patch(
        f"/salons/{salon['id']}/members/{other_account['user']['id']}",
        json={"role": "member"},
        headers=registered,
    )
    assert demoted.status_code == 200
    assert guest.get(f"/salons/{salon['id']}").json()["role"] == "member"


def test_a_moderator_cannot_change_roles(
    client: TestClient, salon, registered, other_account
) -> None:
    third = other_account["client"]
    add_member(client, salon["id"], registered)
    forbidden = third.patch(
        f"/salons/{salon['id']}/members/{other_account['user']['id']}",
        json={"role": "member"},
        headers=other_account["headers"],
    )
    assert forbidden.status_code == 403


def test_owner_role_is_protected(client: TestClient, salon, registered, other_account) -> None:
    owner_id = client.get("/auth/me").json()["id"]
    add_member(client, salon["id"], registered)
    conflict = client.patch(
        f"/salons/{salon['id']}/members/{owner_id}",
        json={"role": "member"},
        headers=registered,
    )
    assert conflict.status_code == 409


def test_role_change_rejects_an_unknown_member(
    client: TestClient, salon, registered, other_account
) -> None:
    missing = client.patch(
        f"/salons/{salon['id']}/members/{'f' * 32}",
        json={"role": "member"},
        headers=registered,
    )
    assert missing.status_code == 404
    invalid = client.patch(
        f"/salons/{salon['id']}/members/{other_account['user']['id']}",
        json={"role": "root"},
        headers=registered,
    )
    assert invalid.status_code == 422


def test_only_owner_can_delete_salon(client: TestClient, salon, registered, other_account) -> None:
    guest = other_account["client"]
    add_member(client, salon["id"], registered)
    forbidden = guest.request("DELETE", f"/salons/{salon['id']}", headers=other_account["headers"])
    assert forbidden.status_code == 403
    assert client.request("DELETE", f"/salons/{salon['id']}", headers=registered).status_code == 200
    assert client.get("/salons").json() == []


def test_only_moderator_can_rename(client: TestClient, salon, registered, other_account) -> None:
    guest = other_account["client"]
    add_member(client, salon["id"], registered)
    demote(client, salon, registered, other_account)
    forbidden = guest.patch(
        f"/salons/{salon['id']}", json={"name": "pique"}, headers=other_account["headers"]
    )
    assert forbidden.status_code == 403
    renamed = client.patch(
        f"/salons/{salon['id']}", json={"name": "nouveau-nom"}, headers=registered
    )
    assert renamed.status_code == 200
    assert client.get(f"/salons/{salon['id']}").json()["name"] == "nouveau-nom"


def test_owner_cannot_be_removed(client: TestClient, salon, registered, other_account) -> None:
    add_member(client, salon["id"], registered)
    unknown = client.request("DELETE", f"/salons/{salon['id']}/members/inconnu", headers=registered)
    assert unknown.status_code == 404
    owner_id = next(
        member["id"]
        for member in client.get(f"/salons/{salon['id']}/members").json()["members"]
        if member["role"] == "owner"
    )
    conflict = client.request(
        "DELETE", f"/salons/{salon['id']}/members/{owner_id}", headers=registered
    )
    assert conflict.status_code == 409


def test_channel_crud_and_name_conflict(client: TestClient, salon, registered) -> None:
    created = client.post(
        f"/salons/{salon['id']}/channels", json={"name": "dev"}, headers=registered
    )
    assert created.status_code == 201
    assert created.json()["kind"] == "text"
    duplicate = client.post(
        f"/salons/{salon['id']}/channels", json={"name": "dev"}, headers=registered
    )
    assert duplicate.status_code == 409
    renamed = client.patch(
        f"/channels/{created.json()['id']}", json={"topic": " discussions"}, headers=registered
    )
    assert renamed.status_code == 200
    assert renamed.json()["topic"] == "discussions"
    deleted = client.request("DELETE", f"/channels/{created.json()['id']}", headers=registered)
    assert deleted.status_code == 200


def test_channel_name_is_validated(client: TestClient, salon, registered) -> None:
    assert (
        client.post(
            f"/salons/{salon['id']}/channels", json={"name": "A"}, headers=registered
        ).status_code
        == 422
    )
    assert (
        client.post(
            f"/salons/{salon['id']}/channels", json={"name": "salut; drop"}, headers=registered
        ).status_code
        == 422
    )


def test_last_channel_cannot_be_deleted(client: TestClient, salon, registered) -> None:
    blocked = client.request("DELETE", f"/channels/{salon['channel_id']}", headers=registered)
    assert blocked.status_code == 409


def test_private_channel_is_hidden_from_non_members(
    client: TestClient, salon, registered, other_account
) -> None:
    private = client.post(
        f"/salons/{salon['id']}/channels",
        json={"name": "staff", "kind": "private"},
        headers=registered,
    ).json()
    guest = other_account["client"]
    add_member(client, salon["id"], registered)
    listed = [item["name"] for item in guest.get(f"/salons/{salon['id']}/channels").json()]
    assert "staff" not in listed
    assert guest.get(f"/channels/{private['id']}").status_code == 404

    # Un canal prive reste invisible : 404, jamais 403, pour ne pas
    # divulguer son existence aux non-membres.
    forbidden = guest.post(
        f"/channels/{private['id']}/members",
        json={"username": "invitee"},
        headers=other_account["headers"],
    )
    assert forbidden.status_code == 404
    granted = client.post(
        f"/channels/{private['id']}/members", json={"username": "invitee"}, headers=registered
    )
    assert granted.status_code == 200
    assert guest.get(f"/channels/{private['id']}").status_code == 200
    access = client.get(f"/channels/{private['id']}/members").json()["members"]
    assert {member["username"] for member in access} == {"augustin", "invitee"}


def test_public_channel_has_no_access_list(client: TestClient, salon, registered) -> None:
    response = client.post(
        f"/channels/{salon['channel_id']}/members",
        json={"username": "invitee"},
        headers=registered,
    )
    assert response.status_code == 409


def test_salon_payload_never_leaks_hashes(client: TestClient, salon, registered) -> None:
    body = client.get("/salons").text + client.get(f"/salons/{salon['id']}/members").text
    assert "password" not in body
    assert "scrypt$" not in body
    assert CIPHERTEXT not in body
