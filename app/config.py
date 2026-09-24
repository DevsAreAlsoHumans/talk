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
    allowed_origins: list[str] = [
        "http://127.0.0.1:8000",
        "http://localhost:8000",
    ]


settings = Settings()