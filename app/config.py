from functools import lru_cache
from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Configuration chargée depuis les variables d'environnement."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
        populate_by_name=True,
    )

    app_name: str = "Talk"
    environment: str = "development"
    redis_url: str = "redis://localhost:6379/0"
    session_cookie_name: str = "talk_session"
    csrf_cookie_name: str = "talk_csrf"
    session_ttl_seconds: int = Field(default=7 * 24 * 60 * 60, ge=300, le=31 * 24 * 60 * 60)
    csrf_ttl_seconds: int = Field(default=15 * 60, ge=60, le=3600)
    cookie_secure: bool = Field(default=False, validation_alias="COOKIE_SECURE")
    allowed_origins: str = "http://localhost:8000,http://127.0.0.1:8000"
    allowed_hosts: str = "localhost,127.0.0.1,testserver"
    registration_rate_limit: int = Field(default=5, ge=1, le=100)
    registration_rate_window: int = Field(default=3600, ge=60, le=86400)
    login_rate_limit: int = Field(default=10, ge=1, le=100)
    login_rate_window: int = Field(default=300, ge=30, le=3600)
    docs_enabled: bool = True
    log_level: str = "INFO"

    @property
    def origin_list(self) -> list[str]:
        return [origin.strip() for origin in self.allowed_origins.split(",") if origin.strip()]

    @property
    def host_list(self) -> list[str]:
        return [host.strip() for host in self.allowed_hosts.split(",") if host.strip()]

    @property
    def is_production(self) -> bool:
        return self.environment.lower() in {"production", "prod"}

    @property
    def frontend_directory(self) -> Path:
        return Path(__file__).resolve().parent.parent / "frontend"


@lru_cache
def get_settings() -> Settings:
    return Settings()
