from fastapi.testclient import TestClient

from app.repositories import messages
from tests.conftest import CIPHERTEXT, IV, envelope


def test_send_and_read_message(client: TestClient, salon, registered) -> None:
    sent = client.post(
        f"/channels/{salon['channel_id']}/messages", json=envelope(), headers=registered
    )
    assert sent.status_code == 201
    body = sent.json()
    assert body["ciphertext"] == CIPHERTEXT
    assert body["iv"] == IV
    assert body["sender_id"]

    page = client.get(f"/channels/{salon['channel_id']}/messages").json()
    assert [item["id"] for item in page["messages"]] == [body["id"]]
    assert page["latest_seq"] == body["seq"]


def test_server_never_sees_plaintext(
    client: TestClient, salon, registered, redis_client
) -> None:
    secret = "mon-secret-en-clair"
    client.post(
        f"/channels/{salon['channel_id']}/messages", json=envelope(), headers=registered
    )
    dumped = "\n".join(
        f"{key} {value}"
        for key in redis_client.scan_iter()
        for value in redis_client.hgetall(key).values()
    )
    assert secret not in dumped
    assert "text" not in dumped


def test_plaintext_field_is_rejected(client: TestClient, salon, registered) -> None:
    """Le schema est strict : impossible d'envoyer un contenu en clair."""
    payload = {**envelope(), "text": "bonjour en clair"}
    response = client.post(
        f"/channels/{salon['channel_id']}/messages", json=payload, headers=registered
    )
    assert response.status_code == 422


def test_short_iv_is_rejected(client: TestClient, salon, registered) -> None:
    response = client.post(
        f"/channels/{salon['channel_id']}/messages",
        json=envelope(iv="AAAA"),
        headers=registered,
    )
    assert response.status_code == 422


def test_non_base64_ciphertext_is_rejected(client: TestClient, salon, registered) -> None:
    response = client.post(
        f"/channels/{salon['channel_id']}/messages",
        json=envelope(ciphertext="<script>alert(1)</script>"),
        headers=registered,
    )
    assert response.status_code == 422


def test_send_requires_authentication_and_csrf(client: TestClient, salon, csrf_headers) -> None:
    url = f"/channels/{salon['channel_id']}/messages"
    assert client.post(url, json=envelope()).status_code == 403
    assert client.post(url, json=envelope(), headers=csrf_headers).status_code == 401


def test_send_requires_channel_access(
    client: TestClient, salon, other_account
) -> None:
    response = other_account["client"].post(
        f"/channels/{salon['channel_id']}/messages",
        json=envelope(),
        headers=other_account["headers"],
    )
    assert response.status_code == 404


def test_history_pagination(client: TestClient, salon, registered) -> None:
    sent = [
        client.post(
            f"/channels/{salon['channel_id']}/messages", json=envelope(), headers=registered
        ).json()
        for _ in range(5)
    ]
    page = client.get(f"/channels/{salon['channel_id']}/messages?limit=2").json()
    assert [item["seq"] for item in page["messages"]] == [4, 5]

    older = client.get(
        f"/channels/{salon['channel_id']}/messages?limit=2&before={page['messages'][0]['seq']}"
    ).json()
    assert [item["seq"] for item in older["messages"]] == [2, 3]


def test_poll_returns_only_new_messages(client: TestClient, salon, registered) -> None:
    url = f"/channels/{salon['channel_id']}/messages/poll"
    assert client.get(url).json()["messages"] == []

    client.post(f"/channels/{salon['channel_id']}/messages", json=envelope(), headers=registered)
    first = client.get(url).json()
    assert len(first["messages"]) == 1

    assert client.get(f"{url}?after={first['latest_seq']}").json()["messages"] == []

    client.post(f"/channels/{salon['channel_id']}/messages", json=envelope(), headers=registered)
    caught_up = client.get(f"{url}?after={first['latest_seq']}").json()
    assert len(caught_up["messages"]) == 1


def test_message_retention_is_bounded(
    client: TestClient, salon, registered, redis_client
) -> None:
    for _ in range(messages.MESSAGE_RETENTION + 5):
        client.post(
            f"/channels/{salon['channel_id']}/messages", json=envelope(), headers=registered
        )
    stored = len(redis_client.zrange(f"channel:{salon['channel_id']}:log", 0, -1))
    assert stored == messages.MESSAGE_RETENTION
    page = client.get(f"/channels/{salon['channel_id']}/messages?limit=100").json()
    assert len(page["messages"]) == 100


def test_message_rate_limit(client: TestClient, salon, registered) -> None:
    response = None
    for _ in range(35):
        response = client.post(
            f"/channels/{salon['channel_id']}/messages", json=envelope(), headers=registered
        )
    assert response is not None
    assert response.status_code == 429
