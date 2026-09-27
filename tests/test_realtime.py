"""Diffusion temps réel, testée sur le registre lui-même.

Le `TestClient` partage un seul cookie jar : il ne peut pas incarner deux
membres distincts sur la même connexion. La diffusion à plusieurs abonnés est
donc vérifiée directement sur `ConnectionManager`, avec de fausses sockets.

Ce test ne prouve que la mécanique de distribution. Il ne dit rien de la
cryptographie, et c'est normal : le registre ne manipule que des trames déjà
chiffrées, qu'il recopie sans les ouvrir.
"""

from __future__ import annotations

from typing import Any

from app.realtime import ConnectionManager


class FakeSocket:
    """Sockette minimale : enregistre ce qu'elle reçoit, peut tomber."""

    def __init__(self, name: str, broken: bool = False) -> None:
        self.name = name
        self.broken = broken
        self.sent: list[dict[str, Any]] = []

    async def send_json(self, payload: dict[str, Any]) -> None:
        if self.broken:
            # Ce que fait Starlette quand la connexion est déjà fermée.
            raise RuntimeError("WebSocket is disconnected")
        self.sent.append(payload)


async def test_une_diffusion_atteint_tous_les_abonnes() -> None:
    manager = ConnectionManager()
    alice, bob = FakeSocket("alice"), FakeSocket("bob")
    for socket in (alice, bob):
        await manager.connect(socket)
        await manager.subscribe("canal-1", socket)

    await manager.broadcast("canal-1", {"type": "message", "ciphertext": "x"})

    assert alice.sent == [{"type": "message", "ciphertext": "x"}]
    assert bob.sent == [{"type": "message", "ciphertext": "x"}]


async def test_une_diffusion_atteint_seulement_le_canal_concerne() -> None:
    manager = ConnectionManager()
    here, elsewhere = FakeSocket("ici"), FakeSocket("ailleurs")
    await manager.connect(here)
    await manager.subscribe("canal-1", here)
    await manager.connect(elsewhere)
    await manager.subscribe("canal-2", elsewhere)

    await manager.broadcast("canal-1", {"type": "message"})

    assert len(here.sent) == 1
    assert elsewhere.sent == []


async def test_l_emetteur_est_exclu_de_sa_propre_diffusion() -> None:
    manager = ConnectionManager()
    sender, receiver = FakeSocket("sender"), FakeSocket("receiver")
    for socket in (sender, receiver):
        await manager.connect(socket)
        await manager.subscribe("canal-1", socket)

    await manager.broadcast("canal-1", {"type": "message"}, exclude=sender)

    assert sender.sent == []
    assert len(receiver.sent) == 1


async def test_une_diffusion_ignore_les_autres_canaux_d_un_meme_socket() -> None:
    """Un socket multi-canaux ne reçoit que le canal visé."""
    manager = ConnectionManager()
    socket = FakeSocket("multi")
    await manager.connect(socket)
    await manager.subscribe("canal-1", socket)
    await manager.subscribe("canal-2", socket)

    await manager.broadcast("canal-1", {"type": "message"})

    assert len(socket.sent) == 1


async def test_une_socket_tombie_est_retiree_du_registre() -> None:
    manager = ConnectionManager()
    dead, alive = FakeSocket("dead", broken=True), FakeSocket("alive")
    for socket in (dead, alive):
        await manager.connect(socket)
        await manager.subscribe("canal-1", socket)

    # Une connexion tombée ne doit pas interrompre la diffusion aux autres.
    await manager.broadcast("canal-1", {"type": "message"})

    assert len(alive.sent) == 1
    assert manager.subscriber_count("canal-1") == 1


async def test_unsouscrire_retire_la_socket() -> None:
    manager = ConnectionManager()
    socket = FakeSocket("alice")
    await manager.connect(socket)
    await manager.subscribe("canal-1", socket)

    await manager.unsubscribe("canal-1", socket)
    await manager.broadcast("canal-1", {"type": "message"})

    assert socket.sent == []
    assert manager.subscriber_count("canal-1") == 0


async def test_se_deconnecter_retire_la_socket_de_tous_ses_canaux() -> None:
    manager = ConnectionManager()
    socket = FakeSocket("alice")
    await manager.connect(socket)
    await manager.subscribe("canal-1", socket)
    await manager.subscribe("canal-2", socket)

    await manager.disconnect(socket)

    assert manager.subscriber_count("canal-1") == 0
    assert manager.subscriber_count("canal-2") == 0
