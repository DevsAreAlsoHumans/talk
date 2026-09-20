"""Fixtures partagées : BDD en mémoire + clients de test (cookies isolés)."""

from datetime import UTC, datetime
from typing import Any

import pytest
from starlette.testclient import TestClient

from app.db import Database, get_db
from app.main import app


class InMemory(Database):
    """Database factice : tests déterministes, sans Mongo."""

    def __init__(self) -> None:
        self.users: dict[str, dict[str, Any]] = {}
        self.rooms: list[dict[str, Any]] = []
        self.channels: list[dict[str, Any]] = []
        self.keys: dict[str, str] = {}
        self.wrapped: dict[tuple[str, str], dict[str, Any]] = {}
        self.seq = 0
        self.channel_seq = 0

    async def get_user_by_username(self, username: str) -> dict[str, Any] | None:
        return self.users.get(username)

    async def create_user(self, username: str, password_hash: str) -> dict[str, Any] | None:
        if username in self.users:
            return None
        self.users[username] = {
            "username": username,
            "password_hash": password_hash,
            "_id": username,
            "created_at": datetime.now(UTC),
        }
        return await self.get_user_by_username(username)

    async def get_user_by_id(self, user_id: str) -> dict[str, Any] | None:
        return self.users.get(user_id)

    async def create_room(self, name: str, owner_id: str) -> dict[str, Any]:
        self.seq += 1
        room = {
            "_id": str(self.seq),
            "name": name,
            "owner_id": owner_id,
            "members": [owner_id],
            "created_at": datetime.now(UTC),
        }
        self.rooms.append(room)
        # Modèle Discord : un salon naît avec un premier canal `general`.
        await self.create_channel(room["_id"], "general")
        return room

    async def get_room_by_id(self, room_id: str) -> dict[str, Any] | None:
        return next((r for r in self.rooms if r["_id"] == room_id), None)

    async def list_rooms_for_user(self, username: str) -> list[dict[str, Any]]:
        return [r for r in self.rooms if username in r["members"]]

    async def add_room_member(self, room_id: str, username: str) -> bool:
        room = await self.get_room_by_id(room_id)
        if room is None or username in room["members"]:
            return False
        room["members"].append(username)
        return True

    async def set_public_key(self, username: str, public_key: str) -> None:
        self.keys[username] = public_key

    async def get_public_key(self, username: str) -> str | None:
        return self.keys.get(username)

    async def set_wrapped_key(self, room_id: str, username: str, blob: dict[str, Any]) -> None:
        self.wrapped[(room_id, username)] = blob

    async def get_wrapped_key(self, room_id: str, username: str) -> dict[str, Any] | None:
        return self.wrapped.get((room_id, username))

    async def create_channel(self, room_id: str, name: str) -> dict[str, Any] | None:
        if await self.get_room_by_id(room_id) is None:
            return None
        for c in self.channels:
            if c["room_id"] == room_id and c["name"] == name:
                return None
        self.channel_seq += 1
        channel = {
            "_id": f"c{self.channel_seq}",
            "room_id": room_id,
            "name": name,
            "created_at": datetime.now(UTC),
            "message_blobs": [],
            "msg_seq": 0,
        }
        self.channels.append(channel)
        return channel

    async def list_channels(self, room_id: str) -> list[dict[str, Any]]:
        return [c for c in self.channels if c["room_id"] == room_id]

    async def get_channel(self, room_id: str, channel_id: str) -> dict[str, Any] | None:
        return next(
            (c for c in self.channels if c["_id"] == channel_id and c["room_id"] == room_id),
            None,
        )

    async def delete_channel(self, room_id: str, channel_id: str) -> bool:
        before = len(self.channels)
        self.channels = [
            c
            for c in self.channels
            if not (c["_id"] == channel_id and c["room_id"] == room_id)
        ]
        return len(self.channels) < before

    async def add_channel_message(
        self, room_id: str, channel_id: str, sender: str, blob: str
    ) -> dict[str, Any] | None:
        channel = await self.get_channel(room_id, channel_id)
        if channel is None:
            return None
        channel["msg_seq"] += 1
        doc = {"n": channel["msg_seq"], "sender": sender, "ts": datetime.now(UTC), "payload": blob}
        channel["message_blobs"].append(doc)
        return doc

    async def get_channel_messages(
        self, room_id: str, channel_id: str, after: int | None = None, limit: int = 200
    ) -> list[dict[str, Any]]:
        channel = await self.get_channel(room_id, channel_id)
        if channel is None:
            return []
        msgs = [m for m in channel["message_blobs"] if after is None or m["n"] > after]
        msgs.sort(key=lambda m: m["n"])
        return msgs[-limit:]

    async def close(self) -> None:
        pass


@pytest.fixture()
def inmemory() -> InMemory:
    db = InMemory()
    app.dependency_overrides[get_db] = lambda: db
    yield db
    app.dependency_overrides.pop(get_db, None)


@pytest.fixture()
def client(inmemory: InMemory) -> TestClient:
    with TestClient(app) as c:
        yield c


@pytest.fixture()
def anonymous(inmemory: InMemory) -> TestClient:
    """Client SANS session : simule un visiteur non authentifié."""
    with TestClient(app) as c:
        yield c


def register(client: TestClient, username: str) -> None:
    csrf = client.get("/api/auth/csrf").json()["csrf_token"]
    r = client.post(
        "/api/auth/register",
        json={"username": username, "password": "P4ssw0rdX!"},
        headers={"X-CSRF-Token": csrf},
    )
    assert r.status_code == 201


def create_room(client: TestClient, name: str = "général") -> str:
    csrf = client.get("/api/auth/csrf").json()["csrf_token"]
    r = client.post("/api/rooms", json={"name": name}, headers={"X-CSRF-Token": csrf})
    assert r.status_code == 201
    return r.json()["id"]


def create_channel(client: TestClient, room_id: str, name: str = "règles") -> str:
    csrf = client.get("/api/auth/csrf").json()["csrf_token"]
    r = client.post(
        f"/api/rooms/{room_id}/channels",
        json={"name": name},
        headers={"X-CSRF-Token": csrf},
    )
    assert r.status_code == 201
    return r.json()["id"]


def first_channel(inmemory: InMemory, room_id: str) -> dict[str, Any]:
    """Canal `general` automatiquement créé avec le salon."""
    for channel in inmemory.channels:
        if channel["room_id"] == room_id:
            return channel
    raise AssertionError("aucun canal créé pour ce salon")


@pytest.fixture()
def two_members(inmemory: InMemory):
    """Alice (propriétaire) + Bob, membres d'un même salon; clients distincts."""
    alice, bob = TestClient(app), TestClient(app)
    with alice, bob:
        register(alice, "alice")
        register(bob, "bob")
        room_id = create_room(alice)
        # Bob rejoint le salon (métadonnée de salle, pas de contenu).
        room = inmemory.rooms[-1]
        room["members"].append("bob")
        yield alice, bob, room_id
