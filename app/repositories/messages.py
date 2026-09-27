"""Messages chiffres : le serveur ne stocke qu'une enveloppe opaque.

Ni cle privee ni contenu en clair n'estjamais accepte par l'API : le
schema est `extra="forbid"`, un champ `text` / `content` est donc refuse.

Modele Redis :
- message:<id>       hash d'enveloppes (jamais de contenu en clair)
- channel:<id>:log   ZSET message_id -> sequence (pagination)
- channel:<id>:seq   compteur monotone d'enveloppes
"""

import uuid
from datetime import UTC, datetime

from redis import Redis

MAX_CIPHERTEXT_LENGTH = 16384
MESSAGE_RETENTION = 500


def _message_key(message_id: str) -> str:
    return f"message:{message_id}"


def _log_key(channel_id: str) -> str:
    return f"channel:{channel_id}:log"


def _seq_key(channel_id: str) -> str:
    return f"channel:{channel_id}:seq"


def store_message(
    redis: Redis,
    *,
    channel_id: str,
    sender_id: str,
    ciphertext: str,
    iv: str,
    key_version: int,
) -> dict:
    """Persiste une enveloppe chiffree et la retourne complete."""
    message_id = uuid.uuid4().hex
    sequence = int(redis.incr(_seq_key(channel_id)))
    sent_at = datetime.now(UTC)
    envelope = {
        "id": message_id,
        "channel_id": channel_id,
        "sender_id": sender_id,
        "ciphertext": ciphertext,
        "iv": iv,
        "key_version": key_version,
        "sent_at": sent_at.isoformat(),
        "seq": sequence,
    }
    redis.hset(_message_key(message_id), mapping={k: str(v) for k, v in envelope.items()})
    redis.zadd(_log_key(channel_id), {message_id: sequence})
    _trim(redis, channel_id)
    return envelope


def _trim(redis: Redis, channel_id: str) -> None:
    """Conserve les MESSAGE_RETENTION derniers messages du canal."""
    key = _log_key(channel_id)
    total = redis.zcard(key)
    if total > MESSAGE_RETENTION:
        obsolete = redis.zrange(key, 0, total - MESSAGE_RETENTION - 1)
        if obsolete:
            redis.zremrangebyrank(key, 0, total - MESSAGE_RETENTION - 1)
            redis.delete(*[_message_key(message_id) for message_id in obsolete])


def get_message(redis: Redis, message_id: str) -> dict | None:
    data = redis.hgetall(_message_key(message_id))
    if not data:
        return None
    return _to_envelope(data)


def _to_envelope(data: dict) -> dict:
    return {
        "id": data.get("id", ""),
        "channel_id": data.get("channel_id", ""),
        "sender_id": data.get("sender_id", ""),
        "ciphertext": data.get("ciphertext", ""),
        "iv": data.get("iv", ""),
        "key_version": int(data.get("key_version", 0)),
        "sent_at": data.get("sent_at", ""),
        "seq": int(data.get("seq", 0)),
    }


def latest_sequence(redis: Redis, channel_id: str) -> int:
    return int(redis.get(_seq_key(channel_id)) or 0)


def list_messages(
    redis: Redis, channel_id: str, *, limit: int, before: int | None = None
) -> list[dict]:
    """Historique du canal, du plus ancien au plus recent.

    before = borne exclusive sur la sequence (pagination vers le haut).
    """
    stop = f"({before}" if before is not None else "+inf"
    message_ids = redis.zrevrangebyscore(_log_key(channel_id), stop, "-inf", start=0, num=limit)
    envelopes = []
    for message_id in reversed(message_ids):
        envelope = get_message(redis, message_id)
        if envelope is not None:
            envelopes.append(envelope)
    return envelopes


def messages_since(redis: Redis, channel_id: str, after: int, limit: int) -> list[dict]:
    """Reprise apres reconnexion :Equivalent d'un polling court."""
    message_ids = redis.zrangebyscore(_log_key(channel_id), f"({after}", "+inf", start=0, num=limit)
    return [envelope for envelope in (get_message(redis, mid) for mid in message_ids) if envelope]


def delete_channel_messages(redis: Redis, channel_id: str) -> None:
    for message_id in redis.zrange(_log_key(channel_id), 0, -1):
        redis.delete(_message_key(message_id))
    redis.delete(_log_key(channel_id), _seq_key(channel_id))
