from pydantic import AliasChoices, Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    mongo_uri: str = Field(
        default="mongodb://localhost:27017",
        validation_alias=AliasChoices("MONGODB_URI", "mongo_uri"),
    )
    mongo_dbname: str = Field(
        default="Talk",
        validation_alias=AliasChoices("MONGODB_DBNAME", "mongo_dbname"),
    )
    session_cookie: str = "talk_session"
    csrf_cookie: str = "talk_csrf_token"
    session_ttl_seconds: int = 7 * 24 * 3600
    cookie_secure: bool = False

    # HSTS — 0 = désactivé. Un navigateur n'honore l'en-tête
    # Strict-Transport-Security que sur une réponse HTTPS : l'envoyer en
    # développement sur http://localhost serait donc inutile, et
    # contre-productif (le navigateur mémoriserait une politique alors
    # qu'aucun certificat n'est en place). D'où un défaut à 0, à activer
    # explicitement derrière HTTPS, par exemple via HSTS_MAX_AGE=31536000.
    hsts_max_age: int = 0

    allowed_origins: list[str] = [
        "http://127.0.0.1:8000",
        "http://localhost:8000",
    ]


settings = Settings()