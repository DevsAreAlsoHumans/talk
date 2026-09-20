"""Temps réel : connexions WebSocket + diffusion des événements via Redis pub/sub.

Les routes HTTP publient un événement sur le canal Redis ``talk:events`` avec la liste
des destinataires (membres du salon au moment de l'envoi). Chaque instance de
l'application écoute ce canal et relaie l'événement aux WebSockets locaux concernés :
cela fonctionne donc aussi avec plusieurs workers/instances.

Seuls des messages *déjà chiffrés* transitent ici.
"""

import asyncio
import contextlib
import json
import logging
from collections.abc import Iterable
from dataclasses import dataclass

from fastapi import WebSocket
from redis.asyncio import Redis

logger = logging.getLogger(__name__)

EVENTS_CHANNEL = "talk:events"


@dataclass(eq=False)
class Connection:
    websocket: WebSocket
    user_id: str
    session_hash: str


class ConnectionManager:
    """Registre des WebSockets connectés à cette instance.

    La présence est dérivée de ce registre : un utilisateur est *en ligne* tant qu'il a
    au moins une connexion ouverte. ``add`` et ``remove`` renvoient si l'utilisateur vient
    de passer en ligne / hors ligne (première connexion ou dernière fermeture), ce qui
    permet de ne notifier les autres que sur les changements d'état.
    """

    def __init__(self) -> None:
        self._connections: dict[str, set[Connection]] = {}
        self._presence_targets: dict[str, dict[str, set[str]]] = {}
        """Cibles de présence par utilisateur (salon → autres membres), calculées à la connexion.

        Elles sont figées quand l'utilisateur passe en ligne et rejouées quand il passe hors
        ligne : la déconnexion n'a alors *aucune* requête Redis à faire (elle peut être plus
        lent que soi, et on préfère signaler vite que quelqu'un est parti).
        """

    def add(self, connection: Connection) -> bool:
        sockets = self._connections.setdefault(connection.user_id, set())
        became_online = not sockets
        sockets.add(connection)
        return became_online

    def remove(self, connection: Connection) -> bool:
        sockets = self._connections.get(connection.user_id)
        if sockets:
            sockets.discard(connection)
            if not sockets:
                del self._connections[connection.user_id]
                return True
        return False

    def is_online(self, user_id: str) -> bool:
        return user_id in self._connections and bool(self._connections[user_id])

    def user_ids(self) -> set[str]:
        return set(self._connections)

    def set_presence_targets(self, user_id: str, targets: dict[str, set[str]]) -> None:
        self._presence_targets[user_id] = targets

    def pop_presence_targets(self, user_id: str) -> dict[str, set[str]]:
        return self._presence_targets.pop(user_id, {})

    async def send_to_users(self, user_ids: Iterable[str], payload: dict) -> None:
        for user_id in user_ids:
            for connection in list(self._connections.get(user_id, ())):
                try:
                    await connection.websocket.send_json(payload)
                except Exception:  # noqa: BLE001 - socket mort : on l'oublie, le client se reconnectera
                    self.remove(connection)

    async def close_session(self, session_hash: str) -> None:
        """Ferme les WebSockets ouverts avec cette session (appelé à la déconnexion)."""
        for sockets in list(self._connections.values()):
            for connection in list(sockets):
                if connection.session_hash == session_hash:
                    self.remove(connection)
                    with contextlib.suppress(Exception):
                        await connection.websocket.close(code=1000)


class EventBus:
    def __init__(self, redis: Redis, manager: ConnectionManager) -> None:
        self._redis = redis
        self._manager = manager
        self._pubsub = None
        self._task: asyncio.Task | None = None

    async def publish(self, event: dict, user_ids: Iterable[str]) -> None:
        envelope = {"user_ids": sorted(user_ids), "event": event}
        await self._redis.publish(EVENTS_CHANNEL, json.dumps(envelope))

    async def start(self) -> None:
        self._pubsub = self._redis.pubsub()
        await self._pubsub.subscribe(EVENTS_CHANNEL)
        self._task = asyncio.create_task(self._listen(), name="talk-event-bus")

    async def stop(self) -> None:
        if self._task:
            self._task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._task
        if self._pubsub:
            with contextlib.suppress(Exception):
                await self._pubsub.unsubscribe(EVENTS_CHANNEL)
                await self._pubsub.aclose()

    async def _listen(self) -> None:
        while True:
            try:
                message = await self._pubsub.get_message(ignore_subscribe_messages=True, timeout=1.0)
                if message is None:
                    await asyncio.sleep(0.01)
                    continue
                envelope = json.loads(message["data"])
                await self._manager.send_to_users(envelope["user_ids"], envelope["event"])
            except asyncio.CancelledError:
                raise
            except Exception:
                logger.exception("Erreur dans la boucle d'événements temps réel")
                await asyncio.sleep(1)
