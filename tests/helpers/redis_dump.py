"""Outil de test : sérialise tout le contenu d'une base Redis pour y chercher des données en clair."""

import json


def _read_value(redis, key: str) -> str:
    key_type = redis.type(key)
    if key_type == "string":
        return redis.get(key)
    if key_type == "hash":
        return json.dumps(redis.hgetall(key))
    if key_type == "set":
        return json.dumps(sorted(redis.smembers(key)))
    if key_type == "zset":
        return json.dumps(redis.zrange(key, 0, -1))
    return ""


def dump_redis(redis) -> str:
    return "".join(f"{key}={_read_value(redis, key)}\n" for key in redis.scan_iter("*"))
