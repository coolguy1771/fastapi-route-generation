"""Main FastAPI application entry point."""

import copy
from contextlib import asynccontextmanager
from typing import Annotated

import httpx
from fastapi import Depends, FastAPI
from fastapi.openapi.utils import get_openapi

import app.state as state
from app.auth import verify_gateway_auth
from app.config import get_settings
from app.logging_config import setup_logging
from app.routes import register_service

# Set up logging
logger = setup_logging()
settings = get_settings()


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan manager."""
    # Initialize HTTP client
    state.http_client = httpx.AsyncClient(timeout=settings.http_timeout)
    services = settings.get_services()

    if settings.gateway_api_key:
        logger.info(
            f"Gateway authentication enabled (header: {settings.gateway_api_key_header})"
        )

    if settings.jwt_secret or settings.jwt_public_key:
        logger.info("JWT validation enabled for OAuth2 scope checking")

    if services:
        logger.info(f"Initializing API Gateway with {len(services)} service(s)...")
        for service in services:
            service_info = await register_service(
                app,
                service,
                state.service_configs,
                state.http_client,
                state.service_security_schemes,
                state.route_security_requirements,
                state.route_callbacks,
            )
            state.registered_services.append(service_info)

        active_count = sum(
            1 for s in state.registered_services if s["status"] == "active"
        )
        total_routes = sum(s["routes"] for s in state.registered_services)
        logger.info(
            f"Gateway ready: {active_count}/{len(services)} services active, "
            f"{total_routes} total routes"
        )
    else:
        logger.warning("Warning: No services configured")

    yield

    if state.http_client:
        await state.http_client.aclose()


app = FastAPI(
    title="Dynamic API Gateway",
    description=(
        "A dynamic API gateway that auto-generates routes from multiple "
        "remote OpenAPI specifications with OAuth2 scope support"
    ),
    version="1.0.0",
    lifespan=lifespan,
)


def custom_openapi():
    """Generate custom OpenAPI schema with callbacks and merged schemas."""
    if app.openapi_schema:
        return app.openapi_schema

    openapi_schema = get_openapi(
        title=app.title,
        version=app.version,
        description=app.description,
        routes=app.routes,
    )

    # Ensure components section exists
    if "components" not in openapi_schema:
        openapi_schema["components"] = {}
    if "schemas" not in openapi_schema["components"]:
        openapi_schema["components"]["schemas"] = {}

    # Merge schema definitions from all service specs
    merged_schemas = openapi_schema["components"]["schemas"]
    # Also create definitions for OpenAPI 2.0 compatibility
    definitions = {}

    for service_name, spec in state.service_openapi_specs.items():
        # Handle OpenAPI 3.0: components/schemas
        components = spec.get("components", {})
        schemas = components.get("schemas", {})
        if schemas:
            for schema_name, schema_def in schemas.items():
                # Prefix schema name with service name to avoid conflicts
                prefixed_name = f"{service_name}_{schema_name}"
                if prefixed_name not in merged_schemas:
                    # Deep copy to avoid modifying original
                    schema_copy = copy.deepcopy(schema_def)
                    merged_schemas[prefixed_name] = schema_copy
                    # Also add to definitions for backward compatibility
                    definitions[prefixed_name] = schema_copy

        # Handle OpenAPI 2.0 (Swagger): definitions -> components/schemas
        spec_definitions = spec.get("definitions", {})
        if spec_definitions:
            for def_name, def_schema in spec_definitions.items():
                # Convert OpenAPI 2.0 schema to 3.0 format if needed
                prefixed_name = f"{service_name}_{def_name}"
                if prefixed_name not in merged_schemas:
                    # Deep copy to avoid modifying original
                    schema_copy = copy.deepcopy(def_schema)
                    merged_schemas[prefixed_name] = schema_copy
                    # Also add to definitions for backward compatibility
                    definitions[prefixed_name] = schema_copy
                    # Also keep original name for references that use /definitions/Order format
                    definitions[def_name] = schema_copy

    # Add definitions for OpenAPI 2.0 compatibility (some tools expect this)
    if definitions:
        openapi_schema["definitions"] = definitions

    # Add callbacks to operations
    paths = openapi_schema.get("paths", {})
    for route_key, callbacks in state.route_callbacks.items():
        method, path = route_key.split(":", 1)
        method_lower = method.lower()

        if path in paths and method_lower in paths[path]:
            paths[path][method_lower]["callbacks"] = callbacks

    app.openapi_schema = openapi_schema
    return app.openapi_schema


# Override OpenAPI schema generation to include callbacks
app.openapi = custom_openapi  # type: ignore[assignment]


@app.get("/", tags=["gateway"])
async def gateway_info(
    _: Annotated[bool, Depends(verify_gateway_auth)],
):
    """Gateway status, services, and security configuration."""
    active_services = [s for s in state.registered_services if s["status"] == "active"]
    return {
        "status": "running",
        "gateway": "Dynamic API Gateway",
        "auth_enabled": bool(settings.gateway_api_key),
        "jwt_validation_enabled": bool(settings.jwt_secret or settings.jwt_public_key),
        "services": {
            "total": len(state.registered_services),
            "active": len(active_services),
            "total_routes": sum(s["routes"] for s in state.registered_services),
        },
        "service_details": state.registered_services,
    }


@app.get("/health", tags=["gateway"])
async def health_check():
    """Health check endpoint (no auth required)."""
    active_services = [s for s in state.registered_services if s["status"] == "active"]
    error_services = [s for s in state.registered_services if s["status"] == "error"]

    return {
        "status": "healthy" if not error_services else "degraded",
        "services": {
            "active": len(active_services),
            "errors": len(error_services),
        },
    }


@app.get("/security", tags=["gateway"])
async def security_info(
    _: Annotated[bool, Depends(verify_gateway_auth)],
):
    """List all security schemes and scopes from backend services."""
    return {
        "security_schemes": state.service_security_schemes,
        "route_requirements": state.route_security_requirements,
    }
