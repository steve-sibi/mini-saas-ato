from functools import lru_cache

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        extra="ignore",
        populate_by_name=True,
    )

    database_url: str = Field(
        default="postgresql+psycopg://postgres:postgres@127.0.0.1:5432/ato_sentinel",
        alias="DATABASE_URL",
    )
    app_secret_key: str = Field(default="change-me-app-secret", alias="APP_SECRET_KEY")
    csrf_secret_key: str = Field(default="change-me-csrf-secret", alias="CSRF_SECRET_KEY")
    datadog_webhook_secret: str = Field(
        default="change-me-datadog-secret",
        alias="DATADOG_WEBHOOK_SECRET",
    )
    turnstile_site_key: str = Field(default="", alias="TURNSTILE_SITE_KEY")
    turnstile_secret_key: str = Field(default="", alias="TURNSTILE_SECRET_KEY")
    dd_site: str = Field(default="us5.datadoghq.com", alias="DD_SITE")
    dd_service: str = Field(default="ato-sentinel", alias="DD_SERVICE")
    dd_env: str = Field(default="dev", alias="DD_ENV")
    rum_app_id: str = Field(default="", alias="RUM_APP_ID")
    rum_client_token: str = Field(default="", alias="RUM_CLIENT_TOKEN")
    geoip_db_path: str = Field(default=".data/geoip/GeoLite2-City.mmdb", alias="GEOIP_DB_PATH")
    maxmind_license_key: str = Field(default="", alias="MAXMIND_LICENSE_KEY")
    session_cookie_name: str = "ato_sid"
    csrf_cookie_name: str = "ato_csrf"
    session_ttl_hours: int = 12
    hmac_tolerance_seconds: int = 60
    analyst_label: str = "ATO Sentinel Analyst View"

    @property
    def is_production(self) -> bool:
        return self.dd_env.lower() in {"prod", "production"}

    @property
    def use_secure_cookies(self) -> bool:
        return self.is_production

    @property
    def allow_debug_geo_overrides(self) -> bool:
        return not self.is_production


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()
