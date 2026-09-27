import json

from fastapi.testclient import TestClient

from tests.conftest import CIPHERTEXT, IV, OTHER_USERNAME, add_member, demote, envelope

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
    assert (
        client.put("/keys", json={"public_key": "<script>"}, headers=registered).status_code == 422
    )


def test_publish_key_requires_csrf(client: TestClient, registered) -> None:
    assert client.put("/keys", json={"public_key": PUBLIC_KEY}).status_code == 403


def test_read_key_of_a_stranger_is_404(client: TestClient, registered, other_account) -> None:
    response = client.get(f"/keys/{other_account['user']['id']}")
    assert response.status_code == 404


def test_read_key_of_a_colleague(client: TestClient, salon, registered, other_account) -> None:
    guest = other_account["client"]
    add_member(client, salon["id"], registered)
    guest.put("/keys", json={"public_key": PUBLIC_KEY}, headers=other_account["headers"])
    found = client.get(f"/keys/{other_account['user']['id']}")
    assert found.status_code == 200
    assert found.json()["public_key"] == PUBLIC_KEY


def test_channel_key_publish_and_read(client: TestClient, salon, registered) -> None:
    wrapped = "d2" * 60
    published = client.put(
        f"/channels/{salon['channel_id']}/key",
        json={"wrapped_key": wrapped, "iv": IV},
        headers=registered,
    )
    assert published.status_code == 200
    body = published.json()
    assert body["version"] == 1
    assert body["from_user_id"] == client.get("/auth/me").json()["id"]
    stored = client.get(f"/channels/{salon['channel_id']}/key")
    assert stored.json()["wrapped_key"] == wrapped


def test_channel_key_iv_is_stored_in_clear(
    client: TestClient, salon, registered, redis_client
) -> None:
    """Le nonce de l'emballage n'est pas un secret : il doit etre relisible.

    Sans lui le destinataire ne peut pas dechiffrer la cle de canal, alors que
    le serveur, lui, conserve indefiniment une enveloppe inutile.
    """
    client.put(
        f"/channels/{salon['channel_id']}/key",
        json={"wrapped_key": "d2" * 60, "iv": IV},
        headers=registered,
    )
    assert client.get(f"/channels/{salon['channel_id']}/key").json()["iv"] == IV
    mine = client.get("/auth/me").json()["id"]
    raw = redis_client.hget(redis_client.keys("channel:*:keys")[0], mine)
    assert json.loads(raw)["iv"] == IV


def test_channel_key_without_iv_is_rejected(client: TestClient, salon, registered) -> None:
    """Une cle emballee sans nonce serait dechiffrable par personne."""
    response = client.put(
        f"/channels/{salon['channel_id']}/key",
        json={"wrapped_key": "d2" * 60},
        headers=registered,
    )
    assert response.status_code == 422


def test_channel_key_iv_must_be_96_bits(client: TestClient, salon, registered) -> None:
    for bad in ("AAAAAAAAAAAAAAAAAAAA", "AAAA", "court", "<script>"):
        response = client.put(
            f"/channels/{salon['channel_id']}/key",
            json={"wrapped_key": "d2" * 60, "iv": bad},
            headers=registered,
        )
        assert response.status_code == 422, bad


def test_channel_key_rotation(client: TestClient, salon, registered) -> None:
    client.put(
        f"/channels/{salon['channel_id']}/key",
        json={"wrapped_key": "d2" * 60, "iv": IV},
        headers=registered,
    )
    rotated = client.put(
        f"/channels/{salon['channel_id']}/key",
        json={"wrapped_key": "e3" * 60, "iv": IV},
        headers=registered,
    )
    assert rotated.json()["version"] == 2


def test_moderator_can_write_another_member_slot(
    client: TestClient, salon, registered, other_account
) -> None:
    target = other_account["user"]["id"]
    add_member(client, salon["id"], registered)
    offered = client.put(
        f"/channels/{salon['channel_id']}/key",
        json={"wrapped_key": "a1" * 60, "user_id": target, "iv": IV},
        headers=registered,
    )
    assert offered.status_code == 200
    assert (
        client.get(f"/channels/{salon['channel_id']}/keys").json()["keys"][target]["from_user_id"]
        == client.get("/auth/me").json()["id"]
    )


def test_member_cannot_overwrite_another_slot(
    client: TestClient, salon, registered, other_account
) -> None:
    """Un membre simple ne peut pas deposer la cle d'un tiers."""
    guest = other_account["client"]
    add_member(client, salon["id"], registered)
    demote(client, salon, registered, other_account)
    forbidden = guest.put(
        f"/channels/{salon['channel_id']}/key",
        json={"wrapped_key": "a1" * 60, "user_id": client.get("/auth/me").json()["id"], "iv": IV},
        headers=other_account["headers"],
    )
    assert forbidden.status_code == 403


def test_cannot_write_slot_of_non_member(
    client: TestClient, salon, registered, other_account
) -> None:
    response = client.put(
        f"/channels/{salon['channel_id']}/key",
        json={"wrapped_key": "a1" * 60, "user_id": "f" * 32, "iv": IV},
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
    owner_key = client.put(
        f"/channels/{private['id']}/key",
        json={"wrapped_key": "d2" * 60, "iv": IV},
        headers=registered,
    )
    assert owner_key.status_code == 200
    assert len(client.get(f"/channels/{private['id']}/keys").json()["keys"]) == 1

    guest = other_account["client"]
    add_member(client, salon["id"], registered)
    # Membre du salon mais pas du canal prive : acces refuse (404, l'existence
    # du canal ne doit pas etre divulguee) et aucune cle deposee possible.
    assert guest.get(f"/channels/{private['id']}/keys").status_code == 404
    refused = guest.put(
        f"/channels/{private['id']}/key",
        json={"wrapped_key": "a1" * 60, "iv": IV},
        headers=other_account["headers"],
    )
    assert refused.status_code == 404

    granted = client.post(
        f"/channels/{private['id']}/members",
        json={"username": OTHER_USERNAME},
        headers=registered,
    )
    assert granted.status_code == 200
    guest_key = guest.put(
        f"/channels/{private['id']}/key",
        json={"wrapped_key": "a1" * 60, "iv": IV},
        headers=other_account["headers"],
    )
    assert guest_key.status_code == 200
    # La liste ne contient que les membres autorises du canal prive.
    assert len(client.get(f"/channels/{private['id']}/keys").json()["keys"]) == 2


def test_channel_key_absent_returns_404(client: TestClient, salon, registered) -> None:
    assert client.get(f"/channels/{salon['channel_id']}/key").status_code == 404


def test_server_never_stores_a_readable_key(client: TestClient, registered, redis_client) -> None:
    client.put("/keys", json={"public_key": PUBLIC_KEY}, headers=registered)
    stored = redis_client.hgetall(redis_client.keys("user:keys:*")[0])
    assert stored["public_key"] == PUBLIC_KEY
    assert set(stored) == {"public_key", "version", "created_at"}


def test_envelope_keys_are_transportable(client: TestClient, salon) -> None:
    assert len(IV) == 16
    assert json.loads(json.dumps(envelope()))["ciphertext"] == CIPHERTEXT
