"""Repository des messages.

Stockage Redis (le serveur ne voit jamais de texte clair) :
- ``room:{id}:seq``       → compteur séquentiel (INCR par message)
- ``room:{id}:messages``  → sorted set ``(score=seq, membre=message:{id})``
- ``message:{id}``        → hash ``{id, seq, room_id, author_id, nonce, ciphertext, created_at}``

Les messages contiennent uniquement du ciphertext + un nonce (base64).
La suppression d'un message conserve son ``seq`` (trous voulus : le tri et la
dédup front par id restent valides, ``ZREVRANGEBYSCORE`` gère les trous).
"""

from __future__ import annotations

import uuid

from redis import Redis

from app.repositories import users

SEQUENCE_SUFFIX = ":seq"
FEED_SUFFIX = ":messages"
MESSAGE_PREFIX = "message:"


def _seq_key(room_id: str) -> str:
    return f"room:{room_id}{SEQUENCE_SUFFIX}"


def _feed_key(room_id: str) -> str:
    return f"room:{room_id}{FEED_SUFFIX}"


def _message_key(message_id: str) -> str:
    return f"{MESSAGE_PREFIX}{message_id}"


def create_message(redis: Redis, room_id: str, author_id: str, nonce: str, ciphertext: str) -> dict:
    """Crée un message chiffré et renvoie son enregistrement ``{id, seq, ...}``."""
    message_id = uuid.uuid4().hex
    seq = redis.incr(_seq_key(room_id))
    message = {
        "id": message_id,
        "seq": seq,
        "room_id": room_id,
        "author_id": author_id,
        "nonce": nonce,
        "ciphertext": ciphertext,
        "created_at": users.iso_utc_now(),
    }
    pipe = redis.pipeline()
    pipe.hset(_message_key(message_id), mapping={k: str(v) for k, v in message.items()})
    pipe.zadd(_feed_key(room_id), {message_id: seq})
    pipe.execute()
    return message


def get_message(redis: Redis, message_id: str) -> dict | None:
    """Renvoie un message hydraté ``{id, seq, ...}`` ou ``None`` s'il n'existe pas."""
    hydrated = _hydrate(redis, [message_id])
    return hydrated[0] if hydrated else None


def delete_message(redis: Redis, message_id: str) -> None:
    """Supprime un message : retrait du feed + purge du hash.

    Le compteur ``room:{id}:seq`` n'est **jamais** décrémenté : les trous de
    ``seq`` sont voulus (compatibilité du tri et dédup front par id).
    """
    message = get_message(redis, message_id)
    if message is None:
        return
    pipe = redis.pipeline()
    pipe.zrem(_feed_key(message["room_id"]), message_id)
    pipe.delete(_message_key(message_id))
    pipe.execute()


def _hydrate(redis: Redis, message_ids: list[str]) -> list[dict]:
    """Hydrate des ids de messages en enregistrements ``{id, seq, ...}``.

    Les ids absents (supprimés) sont silencieusement ignorés — le feed derrière
    une page a pu changer entre la lecture du tri et la lecture des hashes.
    """
    messages = []
    for message_id in message_ids:
        raw = redis.hgetall(_message_key(message_id))
        if not raw:
            continue
        messages.append(
            {
                "id": raw["id"],
                "seq": int(raw["seq"]),
                "room_id": raw["room_id"],
                "author_id": raw["author_id"],
                "nonce": raw["nonce"],
                "ciphertext": raw["ciphertext"],
                "created_at": raw["created_at"],
            }
        )
    return messages


def list_messages_after(redis: Redis, room_id: str, seq: int) -> list[dict]:
    """Messages du salon avec ``seq`` strictement supérieur à ``seq``, triés.

    Utilise la forme exclusive ``(`` de la borne inférieure : ``after=5``
    renvoie les messages 6, 7, 8…
    """
    message_ids = redis.zrangebyscore(_feed_key(room_id), min=f"({seq}", max="+inf")
    return _hydrate(redis, message_ids)


def list_messages_before(redis: Redis, room_id: str, seq: int, limit: int) -> list[dict]:
    """Page des ``limit`` messages strictement antérieurs à ``seq``.

    La borne exclusive ``(seq`` porte sur le ``max`` de ZREVRANGEBYSCORE : l'API
    redis-py de régression inverse prend ``(name, max, min, ...)``, contrairement
    à ``zrangebyscore(name, min, max, ...)`` — avec ``min=`` exclusif on
    obtiendrait une page vide. L'exclusion garantit l'absence de doublon avec le
    message de ``seq`` ; les ids sont inversés pour un affichage croissant.
    """
    message_ids = redis.zrevrangebyscore(
        _feed_key(room_id), min="-inf", max=f"({seq}", start=0, num=limit
    )
    message_ids.reverse()
    return _hydrate(redis, message_ids)


def list_last_messages(redis: Redis, room_id: str, limit: int) -> list[dict]:
    """Les ``limit`` derniers messages du salon, du plus ancien au plus récent."""
    message_ids = redis.zrevrange(_feed_key(room_id), start=0, end=limit - 1)
    message_ids.reverse()
    return _hydrate(redis, message_ids)
