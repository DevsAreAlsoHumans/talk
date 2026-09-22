from pydantic import AliasChoices, Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    mongo_uri: str = Field(
        default="mongodb://localhost:27017",
        validation_alias=AliasChoices("MONGODB_URI", "mongo_uri"),
    )
    mongo_dbname: str = Field(
        default="talk",
        validation_alias=AliasChoices("MONGODB_DBNAME", "mongo_dbname"),
    )


settings = Settings()