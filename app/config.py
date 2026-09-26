from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Configuration de l'application, lue depuis les variables d'environnement."""

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    mongo_uri: str = "mongodb://localhost:27017"
    mongo_db_name: str = "talk"
    redis_uri: str = "redis://localhost:6379/0"
    secret_key: str = "change-me"

    # Mettre à True derrière un reverse proxy HTTPS. En local/CI/Docker sur
    # http://, doit rester False sinon le navigateur refuse de renvoyer le cookie.
    cookie_secure: bool = False
    session_ttl_seconds: int = 60 * 60 * 24 * 7


settings = Settings()
