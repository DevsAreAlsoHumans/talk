from conftest import TEST_ORIGIN, create_room, encrypted_message, register_user
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect


def test_websocket_requires_session_and_origin(app):
    with TestClient(app, base_url=TEST_ORIGIN) as anonymous:
        try:
            with anonymous.websocket_connect("/api/ws", headers={"Origin": TEST_ORIGIN}) as socket:
                socket.receive_json()
        except WebSocketDisconnect as exc:
            assert exc.code == 4401
        else:
            raise AssertionError("Le WebSocket anonyme aurait dû être refusé")

        try:
            with anonymous.websocket_connect(
                "/api/ws", headers={"Origin": "https://attaquant.example"}
            ):
                pass
        except WebSocketDisconnect as exc:
            assert exc.code == 1008
        else:
            raise AssertionError("L'origine étrangère aurait dû être refusée")


def test_authenticated_websocket_receives_encrypted_event(client):
    register_user(client, "alice")
    room_data = create_room(client)
    channel_id = room_data["channels"][0]["id"]

    with client.websocket_connect("/api/ws", headers={"Origin": TEST_ORIGIN}) as socket:
        ready = socket.receive_json()
        assert ready["type"] == "connection.ready"
        socket.send_json({"type": "ping", "nonce": "test"})
        assert socket.receive_json() == {"type": "pong", "nonce": "test"}

        payload = encrypted_message()
        response = client.post(
            f"/api/channels/{channel_id}/messages",
            headers={
                "X-CSRF-Token": room_data["csrf_token"],
                "Origin": TEST_ORIGIN,
            },
            json=payload,
        )
        assert response.status_code == 201
        event = socket.receive_json()
        assert event["type"] == "message.created"
        assert event["message"]["ciphertext"] == payload["ciphertext"]
        assert "plaintext" not in event["message"]


def test_websocket_is_closed_when_session_is_revoked(client):
    registered = register_user(client, "alice")
    with client.websocket_connect("/api/ws", headers={"Origin": TEST_ORIGIN}) as socket:
        assert socket.receive_json()["type"] == "connection.ready"
        logout = client.post(
            "/api/auth/logout",
            headers={
                "X-CSRF-Token": registered["csrf_token"],
                "Origin": TEST_ORIGIN,
            },
        )
        assert logout.status_code == 200
        try:
            socket.receive_json()
        except WebSocketDisconnect as exc:
            assert exc.code == 4401
        else:
            raise AssertionError("La révocation aurait dû fermer le WebSocket")


def test_websocket_rejects_oversized_frames(client):
    register_user(client, "alice")
    with client.websocket_connect("/api/ws", headers={"Origin": TEST_ORIGIN}) as socket:
        assert socket.receive_json()["type"] == "connection.ready"
        socket.send_text("x" * 2049)
        assert socket.receive_json() == {"type": "error", "code": "payload_too_large"}
        try:
            socket.receive_json()
        except WebSocketDisconnect as exc:
            assert exc.code == 1009
        else:
            raise AssertionError("Le WebSocket aurait dû être fermé")
