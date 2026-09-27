import json

import pytest
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

from tests.conftest import IV, envelope

POLICY_VIOLATION = 1008


def _csrf(client: TestClient) -> dict[str, str]:
    return {"X-CSRF-Token": client.cookies.get("csrf_token") or ""}


def test_socket_ready_frame(client: TestClient, salon) -> None:
    with client.websocket_connect(f"/ws/channels/{salon['channel_id']}") as socket:
        ready = json.loads(socket.receive_text())
    assert ready["type"] == "ready"
    assert ready["channel_id"] == salon["channel_id"]
    assert ready["latest_seq"] == 0


def test_socket_requires_session(new_client, salon) -> None:
    anonymous = new_client()
    with pytest.raises(WebSocketDisconnect) as failure:
        with anonymous.websocket_connect(f"/ws/channels/{salon['channel_id']}"):
            pass
    assert failure.value.code == POLICY_VIOLATION


def test_socket_denied_for_non_member(other_account, salon) -> None:
    with pytest.raises(WebSocketDisconnect) as failure:
        with other_account["client"].websocket_connect(f"/ws/channels/{salon['channel_id']}"):
            pass
    assert failure.value.code == POLICY_VIOLATION


def test_socket_rejects_foreign_origin(client: TestClient, salon) -> None:
    with pytest.raises(WebSocketDisconnect) as failure:
        with client.websocket_connect(
            f"/ws/channels/{salon['channel_id']}",
            headers={"origin": "https://attaquant.example"},
        ):
            pass
    assert failure.value.code == POLICY_VIOLATION


def test_socket_broadcasts_to_other_members(client: TestClient, salon, other_account) -> None:
    client.post(
        f"/salons/{salon['id']}/members",
        json={"username": "invitee"},
        headers=_csrf(client),
    )
    guest = other_account["client"]
    url = f"/ws/channels/{salon['channel_id']}"
    with client.websocket_connect(url) as sender, guest.websocket_connect(url) as listener:
        json.loads(sender.receive_text())
        json.loads(listener.receive_text())
        sender.send_text(json.dumps(envelope()))
        frame = json.loads(listener.receive_text())
    assert frame["type"] == "message"
    assert frame["message"]["ciphertext"] == envelope()["ciphertext"]
    assert frame["message"]["iv"] == IV


def test_socket_rejects_plaintext_frame(client: TestClient, salon) -> None:
    with client.websocket_connect(f"/ws/channels/{salon['channel_id']}") as socket:
        json.loads(socket.receive_text())
        socket.send_text(json.dumps({**envelope(), "text": "en clair"}))
        error = json.loads(socket.receive_text())
    assert error["type"] == "error"
    assert error["code"] == "invalid_envelope"


def test_socket_rejects_oversized_frame(client: TestClient, salon) -> None:
    with client.websocket_connect(f"/ws/channels/{salon['channel_id']}") as socket:
        json.loads(socket.receive_text())
        socket.send_text("x" * 20001)
        error = json.loads(socket.receive_text())
    assert error["code"] == "too_large"


def test_socket_message_is_persisted(client: TestClient, salon) -> None:
    with client.websocket_connect(f"/ws/channels/{salon['channel_id']}") as socket:
        json.loads(socket.receive_text())
        socket.send_text(json.dumps(envelope()))
        frame = json.loads(socket.receive_text())
    history = client.get(f"/channels/{salon['channel_id']}/messages").json()
    assert [item["id"] for item in history["messages"]] == [frame["message"]["id"]]
