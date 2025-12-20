"""Pydantic models for service configuration and authentication."""

from enum import Enum
from pydantic import BaseModel


class AuthType(str, Enum):
    """Supported authentication types for backend services."""

    NONE = "none"
    API_KEY_HEADER = "api_key_header"
    API_KEY_QUERY = "api_key_query"
    BEARER = "bearer"
    BASIC = "basic"
    OAUTH2 = "oauth2"


class OAuth2Config(BaseModel):
    """OAuth2 configuration for scope validation."""

    # JWT validation settings
    jwt_secret: str | None = None
    jwt_algorithms: list[str] = ["HS256", "RS256"]
    jwt_audience: str | None = None
    jwt_issuer: str | None = None
    # If true, validate scopes at gateway; if false, just document them
    validate_scopes: bool = False
    # Scopes claim name in JWT (usually "scope" or "scp")
    scopes_claim: str = "scope"


class ServiceAuth(BaseModel):
    """Authentication configuration for a backend service."""

    type: AuthType = AuthType.NONE
    # For API key auth
    api_key: str | None = None
    api_key_header_name: str = "X-API-Key"
    api_key_query_name: str = "api_key"
    # For Bearer token auth
    token: str | None = None
    # For Basic auth
    username: str | None = None
    password: str | None = None
    # Additional custom headers to add to all requests
    custom_headers: dict[str, str] = {}
    # Whether to pass through client's Authorization header to backend
    passthrough_auth: bool = False
    # OAuth2 scope configuration
    oauth2: OAuth2Config = OAuth2Config()


class ServiceConfig(BaseModel):
    """Configuration for a single backend service."""

    name: str
    openapi_url: str
    backend_base_url: str
    prefix: str = ""
    enabled: bool = True
    auth: ServiceAuth = ServiceAuth()
    # Whether to propagate security requirements from backend spec
    propagate_security: bool = True
