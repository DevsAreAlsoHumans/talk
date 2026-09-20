"""Configuration de l'application via des variables d'environnement.

Toutes les valeurs sensibles (SECRET_KEY, REDIS_URL…) passent par
l'environnement — jamais committées.
"""

from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Paramètres applicatifs chargés depuis l'environnement (ou un .env)."""

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    # Clé secrète de l'application (dev : valeur par défaut à surcharger en prod).
    SECRET_KEY: str = "dev-only-secret-key-change-me"
    # URL Redis (schéma redis://, mot de passe optionnel).
    REDIS_URL: str = "redis://localhost:6379/0"
    # Durée de vie d'une session en secondes (7 jours).
    SESSION_TTL: int = 7 * 24 * 60 * 60
    # Nom du cookie de session.
    COOKIE_NAME: str = "session"
    # Cookie Secure uniquement si HTTPS (True en production via l'environnement).
    COOKIE_SECURE: bool = False
    # Nombre maximal d'échecs de connexion avant blocage.
    MAX_LOGIN_ATTEMPTS: int = 10
    # Fenêtre (en secondes) du compteur de rate-limit.
    RATE_LIMIT_WINDOW: int = 900


@lru_cache
def get_settings() -> Settings:
    """Singleton des paramètres (l'environnement n'est lu qu'une fois)."""
    return Settings()


settings = get_settings()
