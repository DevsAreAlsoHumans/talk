"""Repository des messages.

Stockage Redis (le serveur ne voit jamais de texte clair) :
- ``room:{id}:seq``       → compteur séquentiel (INCR par message)
- ``room:{id}:messages``  → sorted set ``(score=seq, membre=message:{id})``
- ``message:{id}``        → hash ``{id, seq, room_id, author_id, nonce, ciphertext, created_at}``

Les messages contiennent uniquement du ciphertext + un nonce (base64).
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


def list_messages_after(redis: Redis, room_id: str, seq: int) -> list[dict]:
    """Messages du salon avec ``seq`` strictement supérieur à ``seq``, triés.

    Utilise la forme exclusive ``(`` de la borne inférieure : ``after=5``
    renvoie les messages 6, 7, 8…
    """
    message_ids = redis.zrangebyscore(_feed_key(room_id), min=f"({seq}", max="+inf")
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
