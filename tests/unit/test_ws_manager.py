"""Gestionnaire de connexions WebSocket : diffusion, présence, robustesse."""

import pytest

from app.messages.ws import ConnectionManager


class FakeWebSocket:
    """Socket factice : enregistre ce qui lui est envoyé."""

    def __init__(self, broken: bool = False):
        self.sent: list[dict] = []
        self.accepted = False
        self.broken = broken

    async def accept(self):
        self.accepted = True

    async def send_json(self, payload):
        if self.broken:
            raise RuntimeError("socket fermée")
        self.sent.append(payload)


@pytest.fixture
def manager():
    return ConnectionManager()


async def test_connect_accepts_and_registers(manager):
    ws = FakeWebSocket()
    await manager.connect("s1", ws, "u1", "alice")
    assert ws.accepted is True
    assert manager.connection_count("s1") == 1


async def test_broadcast_reaches_every_connection(manager):
    a, b = FakeWebSocket(), FakeWebSocket()
    await manager.connect("s1", a, "u1", "alice")
    await manager.connect("s1", b, "u2", "bob")

    await manager.broadcast("s1", {"type": "message", "id": "1"})

    assert a.sent == [{"type": "message", "id": "1"}]
    assert b.sent == [{"type": "message", "id": "1"}]


async def test_broadcast_can_exclude_the_sender(manager):
    """Utilisé pour « X est en train d'écrire » : inutile de se le renvoyer."""
    a, b = FakeWebSocket(), FakeWebSocket()
    await manager.connect("s1", a, "u1", "alice")
    await manager.connect("s1", b, "u2", "bob")

    await manager.broadcast("s1", {"type": "typing"}, exclude=a)

    assert a.sent == []
    assert len(b.sent) == 1


async def test_broadcast_isolates_salons(manager):
    a, b = FakeWebSocket(), FakeWebSocket()
    await manager.connect("s1", a, "u1", "alice")
    await manager.connect("s2", b, "u2", "bob")

    await manager.broadcast("s1", {"type": "message"})

    assert len(a.sent) == 1
    assert b.sent == []


async def test_broadcast_to_unknown_salon_is_harmless(manager):
    await manager.broadcast("inconnu", {"type": "message"})


async def test_dead_socket_is_dropped(manager):
    """Une socket qui lève doit être retirée, sans interrompre la diffusion."""
    good, dead = FakeWebSocket(), FakeWebSocket(broken=True)
    await manager.connect("s1", good, "u1", "alice")
    await manager.connect("s1", dead, "u2", "bob")

    await manager.broadcast("s1", {"type": "message"})

    assert len(good.sent) == 1
    assert manager.connection_count("s1") == 1


async def test_disconnect_removes_the_connection(manager):
    ws = FakeWebSocket()
    await manager.connect("s1", ws, "u1", "alice")
    manager.disconnect("s1", ws)
    assert manager.connection_count("s1") == 0
    # Le salon vide ne doit pas rester en mémoire.
    assert "s1" not in manager.active_connections


async def test_disconnect_is_idempotent(manager):
    ws = FakeWebSocket()
    await manager.connect("s1", ws, "u1", "alice")
    manager.disconnect("s1", ws)
    manager.disconnect("s1", ws)
    manager.disconnect("salon-inconnu", ws)


# ---------- Présence ----------


async def test_online_users_lists_members(manager):
    a, b = FakeWebSocket(), FakeWebSocket()
    await manager.connect("s1", a, "u1", "alice")
    await manager.connect("s1", b, "u2", "bob")

    assert manager.online_users("s1") == [
        {"user_id": "u1", "username": "alice"},
        {"user_id": "u2", "username": "bob"},
    ]


async def test_two_tabs_count_as_one_person(manager):
    """Un utilisateur avec deux onglets ne doit apparaître qu'une fois."""
    tab1, tab2 = FakeWebSocket(), FakeWebSocket()
    await manager.connect("s1", tab1, "u1", "alice")
    await manager.connect("s1", tab2, "u1", "alice")

    assert manager.connection_count("s1") == 2
    assert manager.online_users("s1") == [{"user_id": "u1", "username": "alice"}]


async def test_online_users_is_sorted_case_insensitively(manager):
    a, b = FakeWebSocket(), FakeWebSocket()
    await manager.connect("s1", a, "u1", "Zoe")
    await manager.connect("s1", b, "u2", "alice")

    assert [u["username"] for u in manager.online_users("s1")] == ["alice", "Zoe"]


async def test_online_users_of_empty_salon(manager):
    assert manager.online_users("inconnu") == []


async def test_broadcast_presence_sends_the_roster(manager):
    ws = FakeWebSocket()
    await manager.connect("s1", ws, "u1", "alice")

    await manager.broadcast_presence("s1")

    assert ws.sent == [{"type": "presence", "users": [{"user_id": "u1", "username": "alice"}]}]
