"""Application configuration and settings."""

import json
from functools import lru_cache
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict

from app.models import ServiceConfig


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    services_config: str = "[]"
    services_config_file: str = ""
    http_timeout: float = 30.0

    # Gateway-level authentication
    gateway_api_key: str | None = None
    gateway_api_key_header: str = "X-Gateway-Key"

    # Global JWT validation (applies to all services with oauth2 auth)
    jwt_secret: str | None = None
    jwt_public_key: str | None = None  # For RS256
    jwt_algorithms: str = "HS256,RS256"
    jwt_audience: str | None = None
    jwt_issuer: str | None = None

    # Logging configuration
    log_level: str = "INFO"
    log_format: str = "json"  # "json" or "text"
    log_file: str | None = None  # Optional log file path
    uvicorn_log_level: str = (
        "info"  # Uvicorn log level (debug, info, warning, error, critical)
    )
    fastapi_log_level: str = "info"  # FastAPI log level

    def get_services(self) -> list[ServiceConfig]:
        """Parse and return the list of configured services."""
        if self.services_config_file:
            config_path = Path(self.services_config_file)
            if config_path.exists():
                with open(config_path) as f:
                    data = json.load(f)
                    return [ServiceConfig(**svc) for svc in data]

        if self.services_config and self.services_config != "[]":
            data = json.loads(self.services_config)
            return [ServiceConfig(**svc) for svc in data]

        return []


@lru_cache
def get_settings() -> Settings:
    """Get cached settings instance."""
    return Settings()
