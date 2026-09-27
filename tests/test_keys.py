import json

from fastapi.testclient import TestClient

from tests.conftest import CIPHERTEXT, IV, OTHER_USERNAME, envelope

PUBLIC_KEY = "MCowBQYDK2VwAyEA" + "A" * 43
ROTATED_KEY = "MCowBQYDK2VwAyEB" + "B" * 43


def test_publish_public_key(client: TestClient, registered) -> None:
    response = client.put("/keys", json={"public_key": PUBLIC_KEY}, headers=registered)
    assert response.status_code == 200
    body = response.json()
    assert body["public_key"] == PUBLIC_KEY
    assert body["version"] == 1
    assert body["username"] == "augustin"


def test_public_key_rotation_increments_version(client: TestClient, registered) -> None:
    client.put("/keys", json={"public_key": PUBLIC_KEY}, headers=registered)
    rotated = client.put("/keys", json={"public_key": ROTATED_KEY}, headers=registered)
    assert rotated.json()["version"] == 2
    assert rotated.json()["public_key"] == ROTATED_KEY


def test_private_key_field_is_rejected(client: TestClient, registered) -> None:
    response = client.put(
        "/keys", json={"public_key": PUBLIC_KEY, "private_key": "AAAA"}, headers=registered
    )
    assert response.status_code == 422


def test_malformed_public_key_is_rejected(client: TestClient, registered) -> None:
    too_short = client.put("/keys", json={"public_key": "court"}, headers=registered)
    assert too_short.status_code == 422
    assert client.put(
        "/keys", json={"public_key": "<script>"}, headers=registered
    ).status_code == 422


def test_publish_key_requires_csrf(client: TestClient, registered) -> None:
    assert client.put("/keys", json={"public_key": PUBLIC_KEY}).status_code == 403


def test_read_key_of_a_stranger_is_404(
    client: TestClient, registered, other_account
) -> None:
    response = client.get(f"/keys/{other_account['user']['id']}")
    assert response.status_code == 404


def test_read_key_of_a_colleague(client: TestClient, salon, registered, other_account) -> None:
    guest = other_account["client"]
    guest.post(
        f"/salons/{salon['id']}/members", json={"username": OTHER_USERNAME},
        headers=other_account["headers"],
    )
    guest.put("/keys", json={"public_key": PUBLIC_KEY}, headers=other_account["headers"])
    found = client.get(f"/keys/{other_account['user']['id']}")
    assert found.status_code == 200
    assert found.json()["public_key"] == PUBLIC_KEY


def test_channel_key_publish_and_read(client: TestClient, salon, registered) -> None:
    wrapped = "d2" * 60
    published = client.put(
        f"/channels/{salon['channel_id']}/key",
        json={"wrapped_key": wrapped},
        headers=registered,
    )
    assert published.status_code == 200
    body = published.json()
    assert body["version"] == 1
    assert body["from_user_id"] == client.get("/auth/me").json()["id"]
    stored = client.get(f"/channels/{salon['channel_id']}/key")
    assert stored.json()["wrapped_key"] == wrapped


def test_channel_key_rotation(client: TestClient, salon, registered) -> None:
    client.put(
        f"/channels/{salon['channel_id']}/key",
        json={"wrapped_key": "d2" * 60},
        headers=registered,
    )
    rotated = client.put(
        f"/channels/{salon['channel_id']}/key",
        json={"wrapped_key": "e3" * 60},
        headers=registered,
    )
    assert rotated.json()["version"] == 2


def test_moderator_can_write_another_member_slot(
    client: TestClient, salon, registered, other_account
) -> None:
    target = other_account["user"]["id"]
    client.post(
        f"/salons/{salon['id']}/members", json={"username": "invitee"}, headers=registered
    )
    offered = client.put(
        f"/channels/{salon['channel_id']}/key",
        json={"wrapped_key": "a1" * 60, "user_id": target},
        headers=registered,
    )
    assert offered.status_code == 200
    assert client.get(f"/channels/{salon['channel_id']}/keys").json()["keys"][target][
        "from_user_id"
    ] == client.get("/auth/me").json()["id"]


def test_member_cannot_overwrite_another_slot(
    client: TestClient, salon, registered, other_account
) -> None:
    """Un membre simple ne peut pas deposer la cle d'un tiers."""
    guest = other_account["client"]
    client.post(
        f"/salons/{salon['id']}/members", json={"username": "invitee"}, headers=registered
    )
    forbidden = guest.put(
        f"/channels/{salon['channel_id']}/key",
        json={"wrapped_key": "a1" * 60, "user_id": client.get("/auth/me").json()["id"]},
        headers=other_account["headers"],
    )
    assert forbidden.status_code == 403


def test_cannot_write_slot_of_non_member(
    client: TestClient, salon, registered, other_account
) -> None:
    response = client.put(
        f"/channels/{salon['channel_id']}/key",
        json={"wrapped_key": "a1" * 60, "user_id": "f" * 32},
        headers=registered,
    )
    assert response.status_code == 404


def test_channel_keys_list_excludes_others_when_private(
    client: TestClient, salon, registered, other_account
) -> None:
    private = client.post(
        f"/salons/{salon['id']}/channels",
        json={"name": "staff", "kind": "private"},
        headers=registered,
    ).json()
    client.put(
        f"/channels/{private['id']}/key", json={"wrapped_key": "d2" * 60}, headers=registered
    )
    listed = client.get(f"/channels/{private['id']}/keys").json()["keys"]
    assert len(listed) == 1

    guest = other_account["client"]
    guest.post(
        f"/salons/{salon['id']}/members", json={"username": OTHER_USERNAME},
        headers=other_account["headers"],
    )
    guest.put(
        f"/channels/{private['id']}/key", json={"wrapped_key": "a1" * 60},
        headers=other_account["headers"],
    )
    assert guest.get(f"/channels/{private['id']}/keys").status_code == 404

    client.post(
        f"/channels/{private['id']}/members", json={"username": OTHER_USERNAME},
        headers=registered,
    )
    assert len(client.get(f"/channels/{private['id']}/keys").json()["keys"]) == 2


def test_channel_key_absent_returns_404(client: TestClient, salon, registered) -> None:
    assert client.get(f"/channels/{salon['channel_id']}/key").status_code == 404


def test_server_never_stores_a_readable_key(
    client: TestClient, registered, redis_client
) -> None:
    client.put("/keys", json={"public_key": PUBLIC_KEY}, headers=registered)
    stored = redis_client.hgetall(redis_client.keys("user:keys:*")[0])
    assert stored["public_key"] == PUBLIC_KEY
    assert set(stored) == {"public_key", "version", "created_at"}


def test_envelope_keys_are_transportable(client: TestClient, salon) -> None:
    assert len(IV) == 12
    assert json.loads(json.dumps(envelope()))["ciphertext"] == CIPHERTEXT
