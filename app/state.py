"""Application global state management."""

from typing import Any

import httpx

from app.models import ServiceConfig

# Global state
http_client: httpx.AsyncClient | None = None
registered_services: list[dict[str, Any]] = []
service_configs: dict[str, ServiceConfig] = {}
# Store security schemes and scopes extracted from backend specs
service_security_schemes: dict[str, dict[str, Any]] = {}
route_security_requirements: dict[str, list[dict[str, list[str]]]] = {}
# Store callbacks for OpenAPI schema modification
route_callbacks: dict[
    str, dict[str, Any]
] = {}  # key: "METHOD:path", value: callbacks dict
# Store OpenAPI specs for schema merging
service_openapi_specs: dict[
    str, dict[str, Any]
] = {}  # key: service_name, value: OpenAPI spec
