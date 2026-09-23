"""Configuration de l'application.

Tout provient des variables d'environnement : aucun secret n'est écrit dans le code
ni dans le dépôt. Si ``SECRET_KEY`` est absent, une clé aléatoire est générée au
démarrage (pratique en développement, mais les jetons CSRF ne survivent alors pas
à un redémarrage : définissez ``SECRET_KEY`` en production).
"""

import logging
import secrets

from pydantic import model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

logger = logging.getLogger(__name__)

MIN_SECRET_KEY_LENGTH = 32


class Settings(BaseSettings):
    model_config = SettingsConfigDict(extra="ignore")

    redis_url: str = "redis://localhost:6379/0"
    secret_key: str = ""

    # Origines autorisées pour les requêtes qui modifient l'état et pour le WebSocket
    # (séparées par des virgules, sans slash final).
    allowed_origins: str = "http://localhost:8000,http://127.0.0.1:8000"

    # Cookies : `Secure` activé par défaut. Chrome et Firefox l'acceptent sur
    # http://localhost ; pour Safari ou un autre hôte en HTTP, mettre COOKIE_SECURE=false.
    cookie_secure: bool = True
    # Durée de validité d'une session (cookie HttpOnly + empreinte dans Redis). Longue pour ne
    # pas déconnecter l'utilisateur en cours d'utilisation ; surchargeable par SESSION_TTL_SECONDS.
    session_ttl_seconds: int = 30 * 24 * 3600

    # Limitation de débit : nombre de tentatives autorisées par fenêtre.
    login_ip_limit: int = 20
    login_account_limit: int = 5
    login_window_seconds: int = 60
    register_limit: int = 20
    register_window_seconds: int = 3600
    message_limit: int = 30
    message_window_seconds: int = 10

    @model_validator(mode="after")
    def _ensure_secret_key(self) -> "Settings":
        if not self.secret_key:
            logger.warning("SECRET_KEY absent : clé éphémère générée (dev uniquement).")
            self.secret_key = secrets.token_urlsafe(48)
        elif len(self.secret_key) < MIN_SECRET_KEY_LENGTH:
            raise ValueError(f"SECRET_KEY doit contenir au moins {MIN_SECRET_KEY_LENGTH} caractères")
        return self

    @property
    def allowed_origins_list(self) -> list[str]:
        return [origin.strip().rstrip("/") for origin in self.allowed_origins.split(",") if origin.strip()]

    # Le préfixe `__Host-` impose Secure + Path=/ + pas de Domain : il n'est utilisable
    # que si les cookies sont `Secure`.
    @property
    def session_cookie_name(self) -> str:
        return "__Host-session" if self.cookie_secure else "session"

    @property
    def csrf_cookie_name(self) -> str:
        return "__Host-csrf" if self.cookie_secure else "csrf"
