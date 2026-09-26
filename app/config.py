"""Configuration de l'application, lue depuis l'environnement.

Les valeurs par défaut conviennent au développement local et aux tests.
En production, surcharger au minimum `ENV`, `MONGO_URL` et `APP_ORIGINS`.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from functools import lru_cache

SESSION_COOKIE_NAME = "talk_session"
CSRF_COOKIE_NAME = "talk_csrf"
CSRF_HEADER_NAME = "X-CSRF-Token"

# 7 jours pour une session authentifiée, 1 heure pour une session anonyme
# issue du bootstrap CSRF (avant inscription ou connexion).
DEFAULT_SESSION_TTL_SECONDS = 7 * 24 * 3600
DEFAULT_ANONYMOUS_SESSION_TTL_SECONDS = 3600

# Valeurs OWASP minimales pour Argon2id.
DEFAULT_ARGON2_TIME_COST = 3
DEFAULT_ARGON2_MEMORY_COST = 65536
DEFAULT_ARGON2_PARALLELISM = 4


def _env_str(name: str, default: str) -> str:
    value = os.environ.get(name, "").strip()
    return value or default


def _env_int(name: str, default: int) -> int:
    raw = os.environ.get(name, "").strip()
    if not raw:
        return default
    try:
        parsed = int(raw)
    except ValueError:
        return default
    return parsed if parsed > 0 else default


def _env_bool(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _env_list(name: str, default: tuple[str, ...]) -> tuple[str, ...]:
    raw = os.environ.get(name, "")
    if not raw.strip():
        return default
    return tuple(item.strip() for item in raw.split(",") if item.strip())


@dataclass(frozen=True)
class Settings:
    """Paramètres de l'application, immuables."""

    env: str
    mongo_url: str
    mongo_db_name: str
    app_origins: tuple[str, ...]
    session_ttl_seconds: int
    anonymous_session_ttl_seconds: int
    cookie_secure: bool
    trust_proxy_headers: bool
    argon2_time_cost: int
    argon2_memory_cost: int
    argon2_parallelism: int

    @property
    def is_production(self) -> bool:
        return self.env == "production"


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Renvoie la configuration. Le cache suppose un environnement figé au démarrage."""
    env = _env_str("ENV", "development")
    return Settings(
        env=env,
        mongo_url=_env_str("MONGO_URL", "mongodb://mongo:27017"),
        mongo_db_name=_env_str("MONGO_DB_NAME", "talk"),
        app_origins=_env_list("APP_ORIGINS", ("http://localhost:8000", "http://127.0.0.1:8000")),
        session_ttl_seconds=_env_int("SESSION_TTL_SECONDS", DEFAULT_SESSION_TTL_SECONDS),
        anonymous_session_ttl_seconds=_env_int(
            "ANONYMOUS_SESSION_TTL_SECONDS", DEFAULT_ANONYMOUS_SESSION_TTL_SECONDS
        ),
        cookie_secure=_env_bool("COOKIE_SECURE", env == "production"),
        trust_proxy_headers=_env_bool("TRUST_PROXY_HEADERS", False),
        argon2_time_cost=_env_int("ARGON2_TIME_COST", DEFAULT_ARGON2_TIME_COST),
        argon2_memory_cost=_env_int("ARGON2_MEMORY_COST", DEFAULT_ARGON2_MEMORY_COST),
        argon2_parallelism=_env_int("ARGON2_PARALLELISM", DEFAULT_ARGON2_PARALLELISM),
    )
