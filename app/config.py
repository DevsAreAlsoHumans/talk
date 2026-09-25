from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    app_name: str = "Ronyme"
    app_tagline: str = "La messagerie chiffrée de bout en bout"
    public_url: str = "http://localhost:8000"

    mongodb_url: str = "mongodb://localhost:27017"
    mongodb_db: str = "ronyme"

    jwt_secret: str = "change-me-in-production"
    jwt_access_expire_minutes: int = 15
    jwt_refresh_expire_days: int = 7

    # Rate limiting (anti brute-force / anti-spam)
    rate_limit_login: int = 5
    rate_limit_login_window: int = 300
    rate_limit_signup: int = 3
    rate_limit_signup_window: int = 3600
    rate_limit_message: int = 30
    rate_limit_message_window: int = 60
    rate_limit_attachment: int = 10
    rate_limit_attachment_window: int = 300

    # Analytics interne (sans cookie, sans tiers)
    analytics_enabled: bool = True
    analytics_salt: str = "change-me-analytics-salt"

    model_config = {"env_file": ".env", "env_file_encoding": "utf-8"}


settings = Settings()
