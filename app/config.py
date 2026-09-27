from pydantic_settings import BaseSettings
from pydantic import Field
import secrets


class Settings(BaseSettings):
    # App
    APP_NAME: str = "talk"
    DEBUG: bool = False
    SEED_ADMIN: bool = False
    HOST: str = "0.0.0.0"
    PORT: int = 8000

    # Redis
    REDIS_HOST: str = "redis"
    REDIS_PORT: int = 6379
    REDIS_DB: int = 0
    REDIS_PASSWORD: str | None = None

    # Security
    SECRET_KEY: str = Field(default_factory=lambda: secrets.token_urlsafe(32))
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60 * 24 * 7  # 7 days
    BCRYPT_ROUNDS: int = 12

    # CSRF
    CSRF_SECRET: str = Field(default_factory=lambda: secrets.token_urlsafe(32))
    CSRF_COOKIE_NAME: str = "csrf_token"
    CSRF_HEADER_NAME: str = "X-CSRF-Token"

    # Session
    SESSION_COOKIE_NAME: str = "session"
    SESSION_COOKIE_MAX_AGE: int = 60 * 60 * 24 * 7  # 7 days
    SESSION_COOKIE_SECURE: bool = False  # True in production with HTTPS
    SESSION_COOKIE_HTTPONLY: bool = True
    SESSION_COOKIE_SAMESITE: str = "lax"

    # Rate limiting
    RATE_LIMIT_REQUESTS: int = 100
    RATE_LIMIT_WINDOW: int = 60  # seconds

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"
        extra = "ignore"


settings = Settings()