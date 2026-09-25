"""Endpoint WebSocket : authentification, diffusion, présence, frappe.

httpx ne parle pas WebSocket. On pilote donc directement l'application ASGI :
c'est le protocole réel, sans dépendance supplémentaire, et cela permet de
vérifier aussi les fermetures avec leur code d'erreur.
"""

import asyncio
import json

import pytest

from app.auth.service import create_access_token, create_refresh_token
from app.main import app

TIMEOUT = 3


class WebSocketHarness:
    """Client WebSocket minimal parlant ASGI à l'application."""

    def __init__(self, path: str, token: str | None = None):
        query = f"token={token}".encode() if token else b""
        self.scope = {
            "type": "websocket",
            "asgi": {"version": "3.0", "spec_version": "2.3"},
            "http_version": "1.1",
            "scheme": "ws",
            "path": path,
            "raw_path": path.encode(),
            "query_string": query,
            "root_path": "",
            "headers": [(b"host", b"test")],
            "client": ("127.0.0.1", 12345),
            "server": ("test", 80),
            "subprotocols": [],
        }
        self.to_app: asyncio.Queue = asyncio.Queue()
        self.from_app: asyncio.Queue = asyncio.Queue()
        self.task: asyncio.Task | None = None

    async def __aenter__(self):
        await self.to_app.put({"type": "websocket.connect"})
        self.task = asyncio.create_task(app(self.scope, self.to_app.get, self.from_app.put))
        return self

    async def __aexit__(self, *_):
        await self.to_app.put({"type": "websocket.disconnect", "code": 1000})
        if self.task:
            with_suppress = asyncio.wait_for(asyncio.shield(self.task), timeout=TIMEOUT)
            try:
                await with_suppress
            except (asyncio.TimeoutError, asyncio.CancelledError, Exception):  # noqa: BLE001
                self.task.cancel()

    async def next_event(self) -> dict:
        return await asyncio.wait_for(self.from_app.get(), timeout=TIMEOUT)

    async def accepted(self) -> bool:
        """True si la connexion a été acceptée, False si elle a été fermée."""
        event = await self.next_event()
        return event["type"] == "websocket.accept"

    async def close_code(self) -> int:
        event = await self.next_event()
        assert event["type"] == "websocket.close"
        return event["code"]

    async def send_json(self, payload: dict):
        await self.to_app.put({"type": "websocket.receive", "text": json.dumps(payload)})

    async def receive_json(self) -> dict:
        event = await self.next_event()
        assert event["type"] == "websocket.send"
        return json.loads(event["text"])

    async def receive_until(self, kind: str) -> dict:
        """Ignore les événements intermédiaires (présence, etc.)."""
        for _ in range(10):
            payload = await self.receive_json()
            if payload.get("type") == kind:
                return payload
        raise AssertionError(f"aucun événement de type {kind!r}")


@pytest.fixture
async def alice_token(auth_headers, sample_user):
    me = (await auth_headers.get("/auth/me")).json()
    return create_access_token({"sub": me["id"]})


# ---------- Authentification ----------


async def test_connection_without_token_is_refused(auth_headers, salon_id):
    async with WebSocketHarness(f"/ws/{salon_id}") as ws:
        assert await ws.close_code() == 4001


async def test_invalid_token_is_refused(auth_headers, salon_id):
    async with WebSocketHarness(f"/ws/{salon_id}", token="n-importe-quoi") as ws:
        assert await ws.close_code() == 4001


async def test_refresh_token_is_refused(auth_headers, salon_id):
    """Un jeton de rafraîchissement ne doit pas ouvrir un flux temps réel."""
    me = (await auth_headers.get("/auth/me")).json()
    token = create_refresh_token({"sub": me["id"]})
    async with WebSocketHarness(f"/ws/{salon_id}", token=token) as ws:
        assert await ws.close_code() == 4001


async def test_non_member_is_refused(auth_headers, salon_id, second_user):
    bob = (await auth_headers.get("/auth/users/bob/public-key")).json()
    token = create_access_token({"sub": bob["id"]})
    async with WebSocketHarness(f"/ws/{salon_id}", token=token) as ws:
        assert await ws.close_code() == 4003


async def test_deleted_user_is_refused(auth_headers, salon_id):
    token = create_access_token({"sub": "507f1f77bcf86cd799439011"})
    async with WebSocketHarness(f"/ws/{salon_id}", token=token) as ws:
        assert await ws.close_code() in (4001, 4003)


async def test_member_is_accepted(salon_id, alice_token):
    async with WebSocketHarness(f"/ws/{salon_id}", token=alice_token) as ws:
        assert await ws.accepted() is True


# ---------- Présence ----------


async def test_presence_is_announced_on_connect(salon_id, alice_token):
    async with WebSocketHarness(f"/ws/{salon_id}", token=alice_token) as ws:
        assert await ws.accepted() is True
        presence = await ws.receive_until("presence")
        assert [u["username"] for u in presence["users"]] == ["alice"]


# ---------- Messages ----------


async def test_message_is_persisted_and_broadcast(auth_headers, salon_id, alice_token):
    async with WebSocketHarness(f"/ws/{salon_id}", token=alice_token) as ws:
        await ws.accepted()
        await ws.send_json({"type": "message", "ciphertext": "chiffre", "iv": "iv"})

        event = await ws.receive_until("message")
        assert event["ciphertext"] == "chiffre"
        assert event["sender_username"] == "alice"

    stored = (await auth_headers.get(f"/salons/{salon_id}/messages")).json()["messages"]
    assert [m["ciphertext"] for m in stored] == ["chiffre"]


async def test_message_without_type_is_still_accepted(salon_id, alice_token):
    """Compatibilité : un client qui n'envoie pas `type` poste un message."""
    async with WebSocketHarness(f"/ws/{salon_id}", token=alice_token) as ws:
        await ws.accepted()
        await ws.send_json({"ciphertext": "sans-type", "iv": "iv"})
        event = await ws.receive_until("message")
        assert event["ciphertext"] == "sans-type"


async def test_malformed_message_is_rejected(salon_id, alice_token):
    async with WebSocketHarness(f"/ws/{salon_id}", token=alice_token) as ws:
        await ws.accepted()
        await ws.send_json({"type": "message", "ciphertext": ""})
        error = await ws.receive_until("error")
        assert "invalide" in error["error"].lower()


async def test_unknown_event_type_is_rejected(salon_id, alice_token):
    async with WebSocketHarness(f"/ws/{salon_id}", token=alice_token) as ws:
        await ws.accepted()
        await ws.send_json({"type": "fais-moi-des-cafes"})
        error = await ws.receive_until("error")
        assert error["error"]


async def test_unknown_channel_is_rejected(salon_id, alice_token):
    async with WebSocketHarness(f"/ws/{salon_id}", token=alice_token) as ws:
        await ws.accepted()
        await ws.send_json(
            {
                "type": "message",
                "ciphertext": "x",
                "iv": "iv",
                "channel_id": "507f1f77bcf86cd799439011",
            }
        )
        error = await ws.receive_until("error")
        assert "canal" in error["error"].lower()


async def test_message_flood_is_throttled(salon_id, alice_token):
    from app import ratelimit
    from app.config import settings

    ratelimit.reset()
    async with WebSocketHarness(f"/ws/{salon_id}", token=alice_token) as ws:
        await ws.accepted()
        for _ in range(settings.rate_limit_message):
            await ws.send_json({"type": "message", "ciphertext": "spam", "iv": "iv"})
            await ws.receive_until("message")

        await ws.send_json({"type": "message", "ciphertext": "spam", "iv": "iv"})
        error = await ws.receive_until("error")
        assert "Trop de messages" in error["error"]


# ---------- Frappe en cours ----------


async def test_typing_is_not_echoed_to_the_sender(salon_id, alice_token):
    """On ne doit pas se voir soi-même en train d'écrire : l'auteur est exclu
    de la diffusion, donc seul un message suivant lui revient."""
    async with WebSocketHarness(f"/ws/{salon_id}", token=alice_token) as ws:
        await ws.accepted()
        await ws.receive_until("presence")

        await ws.send_json({"type": "typing"})
        await ws.send_json({"type": "message", "ciphertext": "apres", "iv": "iv"})

        event = await ws.receive_json()
        assert event["type"] == "message"
