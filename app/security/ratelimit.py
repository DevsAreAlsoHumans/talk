"""Rate-limit des tentatives de connexion / inscription.

Compteur Redis ``rl:login:{ip}:{username}`` (INCR + EXPIRE à la première
incrémentation). Au-delà de ``MAX_LOGIN_ATTEMPTS`` échecs dans la fenêtre
``RATE_LIMIT_WINDOW`` secondes, l'utilisateur est bloqué (429).
"""

from __future__ import annotations

from redis import Redis

from app.config import settings


def _key(ip: str, username: str) -> str:
    return f"rl:login:{ip}:{username}"


def login_rate_limited(redis: Redis, ip: str, username: str) -> bool:
    """Incrémente le compteur et indique si l'utilisateur est bloqué.

    Le TTL n'est posé qu'au premier échec de la fenêtre (``nx=True``), une
    fenêtre glissante n'étant pas requise ici.
    """
    key = _key(ip, username)
    attempts = redis.incr(key)
    redis.expire(key, settings.RATE_LIMIT_WINDOW, nx=True)
    return attempts > settings.MAX_LOGIN_ATTEMPTS


def reset_login_rate_limit(redis: Redis, ip: str, username: str) -> None:
    """Réinitialise le compteur (connexion réussie)."""
    redis.delete(_key(ip, username))
