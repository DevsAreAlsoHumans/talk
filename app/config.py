from functools import lru_cache

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    app_name: str = "talk"
    debug: bool = False
    host: str = "127.0.0.1"
    port: int = 8000

    redis_url: str = Field(default="redis://localhost:6379/0")

    # Sessions / CSRF — surcharge obligatoire en production.
    session_secret: str = Field(default="dev-only-insecure-secret")
    session_ttl_seconds: int = 60 * 60 * 24 * 7
    cookie_secure: bool = False
    cookie_samesite: str = "lax"
    csrf_ttl_seconds: int = 60 * 60 * 12

    # Anti bruteforce
    rate_limit_login_max: int = 10
    rate_limit_login_window: int = 300
    rate_limit_register_max: int = 5
    rate_limit_register_window: int = 3600

    # Anti spam sur la messagerie
    rate_limit_message_max: int = 30
    rate_limit_message_window: int = 10

    cors_origins: list[str] = Field(default_factory=list)


@lru_cache
def get_settings() -> Settings:
    return Settings()
