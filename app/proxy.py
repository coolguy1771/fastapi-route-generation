"""Request proxying and handler creation."""

import logging
from typing import Annotated, Any

import httpx
from fastapi import Depends, Request, Response

from app.auth import (
    build_auth_headers,
    validate_oauth2_request,
    verify_gateway_auth,
)
from app.config import get_settings
from app.models import AuthType, ServiceConfig

logger = logging.getLogger("fastapi_route_generation")
settings = get_settings()


async def fetch_openapi_spec(
    url: str,
    service: ServiceConfig | None = None,
) -> dict[str, Any]:
    """Fetch OpenAPI specification from a remote URL."""
    headers = {}
    if service:
        headers = build_auth_headers(service, {})

    async with httpx.AsyncClient() as client:
        response = await client.get(url, headers=headers)
        response.raise_for_status()
        return response.json()


def create_proxy_handler(
    method: str,
    original_path: str,
    service_name: str,
    service_configs: dict[str, ServiceConfig],
    http_client: httpx.AsyncClient,
    required_scopes: list[str] | None = None,
):
    """Create a proxy handler with optional scope validation."""

    async def proxy_handler(
        request: Request,
        _: Annotated[bool, Depends(verify_gateway_auth)],
    ) -> Response:
        service = service_configs.get(service_name)
        if not service:
            return Response(
                content='{"error": "Service configuration not found"}',
                status_code=500,
                media_type="application/json",
            )

        # Validate OAuth2 scopes if configured
        if (
            required_scopes
            and service.auth.type == AuthType.OAUTH2
            and service.auth.oauth2.validate_scopes
        ):
            auth_header = request.headers.get("authorization")
            validate_oauth2_request(auth_header, required_scopes, service)

        # Build target URL
        target_path = original_path
        for param_name, param_value in request.path_params.items():
            target_path = target_path.replace(f"{{{param_name}}}", str(param_value))

        target_url = f"{service.backend_base_url.rstrip('/')}{target_path}"

        # Handle query parameters
        query_params = [
            (k, v)
            for k, v in request.query_params.multi_items()
            if k != "gateway_key"
            and (
                service.auth.type != AuthType.API_KEY_QUERY
                or k != service.auth.api_key_query_name
            )
        ]
        if query_params:
            query_string = "&".join(f"{k}={v}" for k, v in query_params)
            target_url = f"{target_url}?{query_string}"

        if service.auth.type == AuthType.API_KEY_QUERY and service.auth.api_key:
            separator = "&" if "?" in target_url else "?"
            target_url = (
                f"{target_url}{separator}"
                f"{service.auth.api_key_query_name}={service.auth.api_key}"
            )

        # Build headers
        hop_by_hop_headers = {
            "connection",
            "keep-alive",
            "proxy-authenticate",
            "proxy-authorization",
            "te",
            "trailers",
            "transfer-encoding",
            "upgrade",
            "host",
        }
        client_headers = {
            key: value
            for key, value in request.headers.items()
            if key.lower() not in hop_by_hop_headers
            and key.lower() != settings.gateway_api_key_header.lower()
        }

        headers = {**client_headers}
        auth_headers = build_auth_headers(service, client_headers)
        headers.update(auth_headers)

        # Read body
        body = None
        if method.upper() in ("POST", "PUT", "PATCH", "DELETE"):
            body = await request.body()

        # Proxy request
        try:
            backend_response = await http_client.request(
                method=method.upper(),
                url=target_url,
                headers=headers,
                content=body,
                follow_redirects=True,
            )

            response_headers = {
                key: value
                for key, value in backend_response.headers.items()
                if key.lower() not in hop_by_hop_headers
                and key.lower() != "content-encoding"
                and key.lower() != "content-length"
            }

            return Response(
                content=backend_response.content,
                status_code=backend_response.status_code,
                headers=response_headers,
                media_type=backend_response.headers.get("content-type"),
            )
        except httpx.RequestError as e:
            return Response(
                content=f'{{"error": "Backend request failed", "detail": "{str(e)}"}}',
                status_code=502,
                media_type="application/json",
            )

    return proxy_handler
