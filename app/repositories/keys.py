"""Echange de cles.

Le serveur ne detient jamais de secret capable de dechiffrer un message :
- il stocke seulement des cles publiques (verification de signature).
- il transporte des cles de canal chiffrees pour chaque destinataire.

Modele Redis :
- user:keys:<user_id>            hash {public_key, version, created_at}
- channel:<channel_id>:keys      hash user_id destinataire -> JSON {version, wrapped_key, iv, from}
"""

import json
from datetime import UTC, datetime

from redis import Redis

from app.repositories import salons


def _user_keys_key(user_id: str) -> str:
    return f"user:keys:{user_id}"


def _channel_keys_key(channel_id: str) -> str:
    return f"channel:{channel_id}:keys"


def put_public_key(redis: Redis, user_id: str, public_key: str) -> dict:
    """Enregistre la cle publique ; la version doit etre strictement croissante."""
    current = get_public_key(redis, user_id)
    version = 1 if current is None else int(current["version"]) + 1
    payload = {
        "public_key": public_key,
        "version": str(version),
        "created_at": datetime.now(UTC).isoformat(),
    }
    redis.hset(_user_keys_key(user_id), mapping=payload)
    return {"public_key": public_key, "version": version, "created_at": payload["created_at"]}


def get_public_key(redis: Redis, user_id: str) -> dict | None:
    data = redis.hgetall(_user_keys_key(user_id))
    if not data:
        return None
    return {
        "public_key": data.get("public_key", ""),
        "version": int(data.get("version", 0)),
        "created_at": data.get("created_at", ""),
    }


def put_channel_key(
    redis: Redis, channel_id: str, target_id: str, from_id: str, wrapped_key: str, iv: str
) -> dict:
    """Depose la cle de canal chiffree de `from_id` pour le destinataire `target_id`.

    Deux champs sont indispensables :
    - `from_user_id`, seul lui permet au destinataire de savoir avec quelle cle
      publique il doit dechiffrer ;
    - `iv`, le nonce AES-GCM de l'emballage. Ce n'est pas un secret, il circule
      donc en clair : sans lui la cle reste definitivement illisible.
    """
    current = get_channel_key(redis, channel_id, target_id)
    version = 1 if current is None else int(current["version"]) + 1
    payload = {
        "version": version,
        "wrapped_key": wrapped_key,
        "iv": iv,
        "from_user_id": from_id,
    }
    redis.hset(_channel_keys_key(channel_id), target_id, json.dumps(payload))
    return payload


def get_channel_key(redis: Redis, channel_id: str, user_id: str) -> dict | None:
    raw = redis.hget(_channel_keys_key(channel_id), user_id)
    if raw is None:
        return None
    try:
        data = json.loads(raw)
    except ValueError:
        return None
    if not isinstance(data, dict):
        return None
    return {
        "version": int(data.get("version", 0)),
        "wrapped_key": data.get("wrapped_key", ""),
        "iv": data.get("iv", ""),
        "from_user_id": data.get("from_user_id", ""),
    }


def list_channel_keys(redis: Redis, channel: dict) -> dict[str, dict]:
    """Cle de canal chiffree de chaque destinataire legitime du canal.

    Pour un canal prive, seuls les membres explicitement autorises apparaissent :
    c'est ce qui permet a un nouveau membre de lire l'historique.
    """
    channel_id = channel["id"]
    keys: dict[str, dict] = {}
    for target_id in salons.list_member_ids(redis, channel["salon_id"]):
        if channel["kind"] == salons.KIND_PRIVATE and not salons.is_channel_member(
            redis, channel_id, target_id
        ):
            continue
        entry = get_channel_key(redis, channel_id, target_id)
        if entry is not None:
            keys[target_id] = entry
    return keys
