"""Authentication and authorization logic."""

import base64
import secrets
from typing import Any

from fastapi import HTTPException, Security
from fastapi.security import APIKeyHeader, APIKeyQuery
from joserfc import jwt
from joserfc.jwk import OctKey, RSAKey
from joserfc.errors import InvalidTokenError, BadSignatureError, DecodeError

from app.config import Settings, get_settings
from app.models import AuthType, ServiceConfig


# Gateway auth security schemes (lazy initialization)
_gateway_api_key_header: APIKeyHeader | None = None
_gateway_api_key_query: APIKeyQuery | None = None


def _get_gateway_api_key_header() -> APIKeyHeader:
    """Get or create gateway API key header security scheme."""
    global _gateway_api_key_header
    if _gateway_api_key_header is None:
        settings = get_settings()
        _gateway_api_key_header = APIKeyHeader(
            name=settings.gateway_api_key_header,
            auto_error=False,
        )
    return _gateway_api_key_header


def _get_gateway_api_key_query() -> APIKeyQuery:
    """Get or create gateway API key query security scheme."""
    global _gateway_api_key_query
    if _gateway_api_key_query is None:
        _gateway_api_key_query = APIKeyQuery(
            name="gateway_key",
            auto_error=False,
        )
    return _gateway_api_key_query


def _get_jwt_config(
    service: ServiceConfig | None, settings: Settings
) -> tuple[str | None, str | None, list[str]]:
    """Get JWT configuration from service or global settings."""
    if service and service.auth.oauth2.jwt_secret:
        return (
            service.auth.oauth2.jwt_secret,
            None,
            service.auth.oauth2.jwt_algorithms,
        )
    elif settings.jwt_secret:
        algorithms = [alg.strip() for alg in settings.jwt_algorithms.split(",")]
        return (settings.jwt_secret, None, algorithms)
    elif settings.jwt_public_key:
        algorithms = [alg.strip() for alg in settings.jwt_algorithms.split(",")]
        return (None, settings.jwt_public_key, algorithms)
    return (None, None, [])


def _decode_with_key(
    token: str, key: OctKey | RSAKey, algorithms: list[str]
) -> dict[str, Any] | None:
    """Decode JWT token with a specific key."""
    try:
        decoded_token = jwt.decode(token, key, algorithms=algorithms)
        return decoded_token.claims
    except (InvalidTokenError, BadSignatureError, DecodeError):
        return None


def _validate_claims(
    claims: dict[str, Any],
    service: ServiceConfig | None,
    settings: Settings,
) -> bool:
    """Validate JWT claims (audience and issuer)."""
    # Validate audience
    audience = (
        service.auth.oauth2.jwt_audience if service else None
    ) or settings.jwt_audience
    if audience:
        token_aud = claims.get("aud")
        if isinstance(token_aud, list):
            if audience not in token_aud:
                return False
        elif token_aud != audience:
            return False

    # Validate issuer
    issuer = (
        service.auth.oauth2.jwt_issuer if service else None
    ) or settings.jwt_issuer
    if issuer and claims.get("iss") != issuer:
        return False

    return True


def decode_jwt_token(
    token: str,
    service: ServiceConfig | None = None,
    settings: Settings | None = None,
) -> dict[str, Any] | None:
    """Decode and validate a JWT token.

    Args:
        token: The JWT token string to decode
        service: Optional service configuration for service-specific JWT settings
        settings: Optional settings instance (defaults to get_settings())

    Returns:
        Decoded token claims if valid, None otherwise
    """
    if settings is None:
        settings = get_settings()

    jwt_secret, jwt_public_key, algorithms = _get_jwt_config(service, settings)

    if not jwt_secret and not jwt_public_key:
        return None

    # Separate algorithms by type
    symmetric_algs = [alg for alg in algorithms if alg.startswith("HS")]
    asymmetric_algs = [
        alg for alg in algorithms if alg.startswith("RS") or alg.startswith("ES")
    ]

    claims = None

    # Try symmetric key first if available
    if jwt_secret and symmetric_algs:
        key = OctKey.import_key(jwt_secret)
        claims = _decode_with_key(token, key, symmetric_algs)

    # If symmetric failed or not available, try asymmetric
    if not claims and jwt_public_key and asymmetric_algs:
        key = RSAKey.import_key(jwt_public_key)
        claims = _decode_with_key(token, key, asymmetric_algs)

    if not claims:
        return None

    # Validate claims
    if not _validate_claims(claims, service, settings):
        return None

    return claims


def extract_scopes_from_token(
    token_payload: dict[str, Any],
    service: ServiceConfig | None = None,
) -> set[str]:
    """Extract scopes from a decoded JWT token.

    Args:
        token_payload: Decoded JWT token claims
        service: Optional service configuration for custom scopes claim name

    Returns:
        Set of scope strings extracted from the token
    """
    scopes_claim = service.auth.oauth2.scopes_claim if service else "scope"
    scopes_value = token_payload.get(scopes_claim, "")

    # Handle both space-separated string and list formats
    if isinstance(scopes_value, str):
        return set(scopes_value.split()) if scopes_value else set()
    elif isinstance(scopes_value, list):
        return set(scopes_value)

    return set()


async def verify_gateway_auth(
    api_key_header: str | None = Security(_get_gateway_api_key_header),
    api_key_query: str | None = Security(_get_gateway_api_key_query),
    settings: Settings | None = None,
) -> bool:
    """Verify gateway-level authentication if configured.

    Args:
        api_key_header: API key from header
        api_key_query: API key from query parameter
        settings: Optional settings instance (defaults to get_settings())

    Returns:
        True if authentication passes or is not required

    Raises:
        HTTPException: If authentication is required but missing or invalid
    """
    if settings is None:
        settings = get_settings()

    if not settings.gateway_api_key:
        return True

    api_key = api_key_header or api_key_query
    if not api_key:
        raise HTTPException(
            status_code=401,
            detail="Gateway API key required",
            headers={"WWW-Authenticate": "ApiKey"},
        )

    if not secrets.compare_digest(api_key, settings.gateway_api_key):
        raise HTTPException(
            status_code=403,
            detail="Invalid gateway API key",
        )

    return True


def validate_scopes(
    required_scopes: list[str],
    token_scopes: set[str],
) -> bool:
    """Check if token has all required scopes.

    Args:
        required_scopes: List of scopes required for the operation
        token_scopes: Set of scopes present in the token

    Returns:
        True if all required scopes are present, False otherwise
    """
    if not required_scopes:
        return True
    return all(scope in token_scopes for scope in required_scopes)


def validate_oauth2_request(
    authorization_header: str | None,
    required_scopes: list[str],
    service: ServiceConfig,
    settings: Settings | None = None,
) -> dict[str, Any]:
    """Validate OAuth2 request with JWT token and scope checking.

    Args:
        authorization_header: Authorization header value from request
        required_scopes: List of scopes required for the operation
        service: Service configuration
        settings: Optional settings instance (defaults to get_settings())

    Returns:
        Decoded token claims if validation passes

    Raises:
        HTTPException: If validation fails
    """
    if settings is None:
        settings = get_settings()

    # Check for Bearer token
    if not authorization_header or not authorization_header.lower().startswith(
        "bearer "
    ):
        raise HTTPException(
            status_code=401,
            detail="Bearer token required",
            headers={"WWW-Authenticate": f'Bearer scope="{" ".join(required_scopes)}"'},
        )

    # Extract token
    token = authorization_header[7:]  # Remove "Bearer "

    # Decode and validate token
    token_payload = decode_jwt_token(token, service, settings)
    if not token_payload:
        raise HTTPException(
            status_code=401,
            detail="Invalid or expired token",
            headers={"WWW-Authenticate": 'Bearer error="invalid_token"'},
        )

    # Validate scopes
    token_scopes = extract_scopes_from_token(token_payload, service)
    if not validate_scopes(required_scopes, token_scopes):
        raise HTTPException(
            status_code=403,
            detail=(
                f"Insufficient scopes. Required: {required_scopes}, "
                f"provided: {list(token_scopes)}"
            ),
            headers={
                "WWW-Authenticate": (
                    f'Bearer error="insufficient_scope" '
                    f'scope="{" ".join(required_scopes)}"'
                )
            },
        )

    return token_payload


def build_auth_headers(
    service: ServiceConfig,
    client_headers: dict[str, str],
) -> dict[str, str]:
    """Build authentication headers for a backend request.

    Args:
        service: Service configuration
        client_headers: Headers from the client request

    Returns:
        Dictionary of authentication headers to add to backend request
    """
    headers = {}
    auth = service.auth

    # Add custom headers first
    headers.update(auth.custom_headers)

    # Add service-specific auth headers
    match auth.type:
        case AuthType.API_KEY_HEADER:
            if auth.api_key:
                headers[auth.api_key_header_name] = auth.api_key

        case AuthType.BEARER:
            if auth.token:
                headers["Authorization"] = f"Bearer {auth.token}"

        case AuthType.BASIC:
            if auth.username and auth.password:
                credentials = base64.b64encode(
                    f"{auth.username}:{auth.password}".encode()
                ).decode()
                headers["Authorization"] = f"Basic {credentials}"

        case AuthType.OAUTH2 | AuthType.NONE:
            pass

    # Pass through client's Authorization header if configured
    if auth.passthrough_auth and "authorization" in client_headers:
        headers["Authorization"] = client_headers["authorization"]

    return headers
