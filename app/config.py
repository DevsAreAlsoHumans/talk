"""Configuration — chargée depuis l'environnement (.env supporté).

Règle : AUCUN secret en dur dans le code. Tout vient des variables d'env.
"""

from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_prefix="TALK_", extra="ignore")

    mongodb_uri: str = "mongodb://localhost:27017"
    db_name: str = "talk"
    # Secret JWT : OBLIGATOIRE de le remplacer en prod (`openssl rand -hex 32`)
    jwt_secret: str = "dev-only-secret-change-me-0123456789abcdef0123456789abcdef"  # noqa: S105
    jwt_algorithm: str = "HS256"
    # Session courte (+ renouvelable) : limite la fenêtre d'utilisation d'un vol
    jwt_expires_seconds: int = 60 * 60 * 24 * 7

    # En prod : COOKIE_SECURE=true -> cookies transmis uniquement en HTTPS
    cookie_secure: bool = False
    # SameSite=strict : le navigateur n'envoie plus les cookies sur les
    # requêtes cross-site -> neutralise la majorité des attaques CSRF
    cookie_samesite: str = "strict"
    cookie_domain: str | None = None

    # Allowlist stricte du CORS : vide = aucune origine externe acceptée
    cors_origins: list[str] = []


@lru_cache
def get_settings() -> Settings:
    return Settings()
