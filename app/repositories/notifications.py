"""Accès Redis aux notifications de messages, du point de vue du destinataire.

L'état des non-lus vit côté serveur : il survit donc à un refresh, à un onglet fermé et
au changement de machine, ce qu'un simple ``Set`` JavaScript ne peut pas faire.

Clés (toutes préfixées par l'identifiant du destinataire) :
  notif:{id}          zset   historique récent (JSON, score = séquence), borné à NOTIFICATION_LIMIT
  notif:{id}:seq      entier prochaine séquence de notification
  notif:{id}:unread   hash   fil → nombre de messages non lus dans ce fil
  notif:{id}:latest   hash   fil → dernière notification, pour regrouper les rafales

Une notification ne décrit **jamais** le contenu d'un message : le serveur ne sait pas le
déchiffrer. Elle dit qui a écrit, dans quel fil et de quel type d'envoi (texte, image,
vocal) ; c'est au client de décider quoi afficher, et au client seul.
"""

import json
from collections.abc import Callable
from datetime import UTC, datetime
from uuid import uuid4

from redis.asyncio import Redis

NOTIFICATION_LIMIT = 100
"""Nombre de lignes conservées par utilisateur : au-delà, les plus anciennes sont oubliées."""

COALESCE_WINDOW_SECONDS = 120
"""Deux messages du même auteur dans le même fil s'effondrent en une ligne pendant ce délai."""


def thread_key(kind: str, thread_id: str) -> str:
    """Clé de fil des notifications, préfixée pour ne jamais confondre salon et conversation."""
    return f"{kind}:{thread_id}"


def _now() -> str:
    return datetime.now(UTC).isoformat(timespec="milliseconds")


def _new_notification(
    *,
    seq: int,
    key: str,
    kind: str,
    thread_id: str,
    label: str,
    sender_username: str,
    message_kind: str,
    created_at: str,
) -> dict:
    return {
        "id": str(uuid4()),
        "seq": seq,
        "thread_key": key,
        "thread_kind": kind,
        "thread_id": thread_id,
        "thread_label": label,
        "sender_username": sender_username,
        "kind": message_kind,
        "count": 1,
        "read": False,
        "created_at": created_at,
        "updated_at": created_at,
    }


def _is_same_burst(previous: dict, sender_username: str, created_at: str) -> bool:
    """Vrai si l'on peut fusionner le nouveau message dans la ligne précédente du même fil."""
    if previous["sender_username"] != sender_username or previous.get("read"):
        return False
    since = datetime.fromisoformat(created_at) - datetime.fromisoformat(previous["created_at"])
    return 0 <= since.total_seconds() < COALESCE_WINDOW_SECONDS


class NotificationRepository:
    def __init__(self, redis: Redis) -> None:
        self._redis = redis

    def _feed_key(self, user_id: str) -> str:
        return f"notif:{user_id}"

    def _seq_key(self, user_id: str) -> str:
        return f"notif:{user_id}:seq"

    def _unread_key(self, user_id: str) -> str:
        return f"notif:{user_id}:unread"

    def _latest_key(self, user_id: str) -> str:
        return f"notif:{user_id}:latest"

    async def create(
        self,
        *,
        user_id: str,
        kind: str,
        thread_id: str,
        label: str,
        sender_username: str,
        message_kind: str,
    ) -> dict:
        """Enregistre une notification pour ``user_id`` et renvoie la ligne à lui diffuser."""
        key = thread_key(kind, thread_id)
        now = _now()
        latest_raw = await self._redis.hget(self._latest_key(user_id), key)
        latest = json.loads(latest_raw) if latest_raw else None
        if latest is not None and _is_same_burst(latest, sender_username, now):
            return await self._coalesce(user_id, key, latest)
        return await self._append(user_id, key, kind, thread_id, label, sender_username, message_kind, now)

    async def _append(
        self,
        user_id: str,
        key: str,
        kind: str,
        thread_id: str,
        label: str,
        sender_username: str,
        message_kind: str,
        created_at: str,
    ) -> dict:
        seq = await self._redis.incr(self._seq_key(user_id))
        notification = _new_notification(
            seq=seq,
            key=key,
            kind=kind,
            thread_id=thread_id,
            label=label,
            sender_username=sender_username,
            message_kind=message_kind,
            created_at=created_at,
        )
        member = json.dumps(notification)
        async with self._redis.pipeline(transaction=True) as pipe:
            pipe.zadd(self._feed_key(user_id), {member: seq})
            # On garde les NOTIFICATION_LIMIT plus récentes : les plus anciennes sortent par le bas.
            pipe.zremrangebyrank(self._feed_key(user_id), 0, -(NOTIFICATION_LIMIT + 1))
            pipe.hset(self._latest_key(user_id), key, member)
            pipe.hincrby(self._unread_key(user_id), key, 1)
            await pipe.execute()
        return notification

    async def _coalesce(self, user_id: str, key: str, previous: dict) -> dict:
        """Fusionne le message dans la ligne précédente : une rafale reste une seule ligne, décomptée.

        Le membre d'un sorted set est immuable : la ligne est donc réécrite à score identique.
        """
        notification = {
            **previous,
            "count": previous["count"] + 1,
            "read": False,
            "updated_at": _now(),
        }
        member = json.dumps(notification)
        async with self._redis.pipeline(transaction=True) as pipe:
            pipe.zrem(self._feed_key(user_id), json.dumps(previous))
            pipe.zadd(self._feed_key(user_id), {member: previous["seq"]})
            pipe.hset(self._latest_key(user_id), key, member)
            pipe.hincrby(self._unread_key(user_id), key, 1)
            await pipe.execute()
        return notification

    async def feed(self, user_id: str, *, limit: int) -> tuple[list[dict], dict[str, int], int]:
        """Renvoie (notifications les plus récentes, non-lus par fil, total des non-lus)."""
        # `execute()` doit rester dans le bloc : en sortir vide la file de commandes du pipeline.
        async with self._redis.pipeline(transaction=False) as pipe:
            pipe.zrevrange(self._feed_key(user_id), 0, limit - 1)
            pipe.hgetall(self._unread_key(user_id))
            rows, unread_rows = await pipe.execute()
        notifications = [json.loads(member) for member in rows]
        unread = {key: int(value) for key, value in unread_rows.items()}
        return notifications, unread, sum(unread.values())

    async def mark_thread_read(self, user_id: str, key: str) -> None:
        """Efface les non-lus d'un fil : le compteur retombe à zéro et ses lignes passent à « lu ».

        La référence de la dernière ligne disparaît aussi : le prochain message de ce fil
        repartira d'une ligne neuve plutôt que d'être fusionné avec une ligne déjà lue.
        """
        if not await self._redis.hexists(self._unread_key(user_id), key):
            return  # déjà à jour : inutile d'écrire
        await self._flag_read(user_id, lambda notification: notification["thread_key"] == key)
        async with self._redis.pipeline(transaction=True) as pipe:
            pipe.hdel(self._unread_key(user_id), key)
            pipe.hdel(self._latest_key(user_id), key)
            await pipe.execute()

    async def mark_all_read(self, user_id: str) -> None:
        """Tout marquer comme lu, quel que soit le fil."""
        if not await self._redis.exists(self._unread_key(user_id)):
            return
        await self._flag_read(user_id, lambda notification: not notification["read"])
        async with self._redis.pipeline(transaction=True) as pipe:
            pipe.delete(self._unread_key(user_id))
            pipe.delete(self._latest_key(user_id))
            await pipe.execute()

    async def _flag_read(self, user_id: str, matches: Callable[[dict], bool]) -> None:
        """Bascule ``read`` à vrai sur les lignes de l'historique correspondant au filtre.

        L'historique est borné à NOTIFICATION_LIMIT lignes : le réécrire à la demande est
        donc une opération petite et bornée, à la différence d'une recherche par motif.
        """
        rows = await self._redis.zrange(self._feed_key(user_id), 0, -1, withscores=True)
        rewrites: list[tuple[str, float]] = []
        stale: list[str] = []
        for member, score in rows:
            notification = json.loads(member)
            if not notification["read"] and matches(notification):
                rewrites.append((json.dumps({**notification, "read": True}), score))
                stale.append(member)
        if not rewrites:
            return
        async with self._redis.pipeline(transaction=True) as pipe:
            pipe.zrem(self._feed_key(user_id), *stale)
            pipe.zadd(self._feed_key(user_id), dict(rewrites))
            await pipe.execute()
