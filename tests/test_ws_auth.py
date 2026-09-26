"""Authentification WebSocket par cookie et contrôle strict de l'origine."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

from app.config import SESSION_COOKIE_NAME
from tests.conftest import TEST_ORIGIN, register_user

POLICY_VIOLATION = 1008


def test_websocket_without_session_is_closed(client: TestClient) -> None:
    with pytest.raises(WebSocketDisconnect) as caught:
        with client.websocket_connect("/ws", headers={"Origin": TEST_ORIGIN}):
            pass

    assert caught.value.code == POLICY_VIOLATION


def test_websocket_with_invalid_session_cookie_is_closed(client: TestClient) -> None:
    """Un cookie bien formé mais inconnu du serveur doit être refusé."""
    client.get("/auth/csrf")
    client.cookies.set(SESSION_COOKIE_NAME, "jeton-que-personne-ne-connait")

    with pytest.raises(WebSocketDisconnect) as caught:
        with client.websocket_connect("/ws", headers={"Origin": TEST_ORIGIN}):
            pass

    assert caught.value.code == POLICY_VIOLATION


def test_websocket_with_valid_session_is_accepted(client: TestClient) -> None:
    username = register_user(client)

    with client.websocket_connect("/ws", headers={"Origin": TEST_ORIGIN}) as websocket:
        payload = websocket.receive_json()

    assert payload["status"] == "connecté"
    assert payload["user"]["username"] == username


def test_websocket_with_invalid_origin_is_closed(client: TestClient) -> None:
    register_user(client)

    with pytest.raises(WebSocketDisconnect) as caught:
        with client.websocket_connect("/ws", headers={"Origin": "http://evil.example"}):
            pass

    assert caught.value.code == POLICY_VIOLATION


def test_websocket_without_origin_is_closed(client: TestClient) -> None:
    """Les navigateurs envoient toujours Origin : son absence est un refus."""
    register_user(client)

    with pytest.raises(WebSocketDisconnect) as caught:
        with client.websocket_connect("/ws"):
            pass

    assert caught.value.code == POLICY_VIOLATION


def test_websocket_origin_is_checked_before_the_session(client: TestClient) -> None:
    """Une origine non fiable doit être rejetée même avec une session valide."""
    register_user(client)

    with pytest.raises(WebSocketDisconnect) as caught:
        with client.websocket_connect("/ws", headers={"Origin": "http://autre.example:8000"}):
            pass

    assert caught.value.code == POLICY_VIOLATION
