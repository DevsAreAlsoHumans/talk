from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    app_name: str = "talk"
    use_mongo: bool = False
    session_ttl_seconds: int = 60 * 60 * 12
    cookie_secure: bool = False
    allowed_origin: str = "http://localhost:8000"
    mongo_url: str = "mongodb://mongo:27017"
    mongo_database: str = "talk"

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")


settings = Settings()
