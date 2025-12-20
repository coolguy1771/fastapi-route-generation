"""Route registration logic."""

import logging
from typing import Any

import httpx
from fastapi import FastAPI

import app.state as state
from app.models import AuthType, ServiceConfig
from app.openapi import (
    build_openapi_extra,
    extract_security_from_spec,
    get_operation_security,
)
from app.proxy import create_proxy_handler, fetch_openapi_spec

logger = logging.getLogger("fastapi_route_generation")


def register_routes_from_openapi(
    app: FastAPI,
    spec: dict[str, Any],
    service: ServiceConfig,
    service_configs: dict[str, ServiceConfig],
    http_client: httpx.AsyncClient,
    service_security_schemes: dict[str, dict[str, Any]],
    route_security_requirements: dict[str, list[dict[str, list[str]]]],
    route_callbacks: dict[str, dict[str, Any]],
) -> int:
    """Parse OpenAPI spec and register routes with security requirements."""
    paths = spec.get("paths", {})
    route_count = 0
    http_methods = ["get", "post", "put", "patch", "delete", "options", "head"]
    prefix = service.prefix.rstrip("/") if service.prefix else ""

    # Extract and store security schemes
    if service.propagate_security:
        security_info = extract_security_from_spec(spec, service.name)
        service_security_schemes[service.name] = security_info

    for path, path_item in paths.items():
        if not isinstance(path_item, dict):
            continue

        for method in http_methods:
            if method not in path_item:
                continue

            operation = path_item[method]
            if not isinstance(operation, dict):
                continue

            base_operation_id = operation.get(
                "operationId",
                f"{method}_{path.replace('/', '_').replace('{', '').replace('}', '')}",
            )
            operation_id = f"{service.name}_{base_operation_id}"
            summary = operation.get("summary", "")
            description = operation.get("description", "")
            if not description and summary:
                description = summary
            original_tags = operation.get("tags", [])
            tags = [service.name] + original_tags

            gateway_path = f"{prefix}{path}"

            # Extract security requirements for this operation
            security_reqs = []
            required_scopes: list[str] = []

            if service.propagate_security:
                security_reqs = get_operation_security(operation, spec, service.name)
                route_security_requirements[f"{method.upper()}:{gateway_path}"] = (
                    security_reqs
                )

                # Collect all required scopes for validation
                for req in security_reqs:
                    for scopes in req.values():
                        required_scopes.extend(scopes)

            # Add scope info to description if present
            if required_scopes:
                scope_info = f"\n\n**Required Scopes:** `{', '.join(required_scopes)}`"
                description = (description or "") + scope_info

            # Build OpenAPI extra for proper documentation
            openapi_extra = build_openapi_extra(operation, path_item, spec)

            # Create handler with scope requirements
            handler = create_proxy_handler(
                method,
                path,
                service.name,
                service_configs,
                http_client,
                required_scopes if required_scopes else None,
            )
            handler.__name__ = operation_id
            handler.__doc__ = description or summary

            # Extract and store callbacks if present (for OpenAPI schema)
            callbacks = operation.get("callbacks", {})
            if callbacks:
                # Store callbacks to add to OpenAPI schema later
                route_key = f"{method.upper()}:{gateway_path}"
                route_callbacks[route_key] = callbacks
                callback_count = sum(
                    len(path_item_cb) if isinstance(path_item_cb, dict) else 0
                    for callback_def in callbacks.values()
                    if isinstance(callback_def, dict)
                    for path_item_cb in callback_def.values()
                    if isinstance(path_item_cb, dict)
                )
                logger.debug(
                    f"      Callbacks: {callback_count} callback route(s) found"
                )

            app.add_api_route(
                path=gateway_path,
                endpoint=handler,
                methods=[method.upper()],
                tags=tags,
                summary=summary,
                description=description,
                operation_id=operation_id,
                openapi_extra=openapi_extra if openapi_extra else None,
            )

            route_count += 1
            scope_str = (
                f" [scopes: {', '.join(required_scopes)}]" if required_scopes else ""
            )
            logger.info(
                f"    {method.upper()} {gateway_path} -> "
                f"{service.backend_base_url}{path}{scope_str}"
            )

    return route_count


async def register_service(
    app: FastAPI,
    service: ServiceConfig,
    service_configs: dict[str, ServiceConfig],
    http_client: httpx.AsyncClient,
    service_security_schemes: dict[str, dict[str, Any]],
    route_security_requirements: dict[str, list[dict[str, list[str]]]],
    route_callbacks: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    """Register routes for a single service."""
    service_configs[service.name] = service

    service_info = {
        "name": service.name,
        "openapi_url": service.openapi_url,
        "backend_url": service.backend_base_url,
        "prefix": service.prefix or "/",
        "status": "unknown",
        "routes": 0,
        "error": None,
        "auth_type": service.auth.type.value,
        "propagate_security": service.propagate_security,
        "validate_scopes": (
            service.auth.oauth2.validate_scopes
            if service.auth.type == AuthType.OAUTH2
            else False
        ),
    }

    if not service.enabled:
        service_info["status"] = "disabled"
        logger.info(f"  [{service.name}] Skipped (disabled)")
        return service_info

    auth_info = (
        f" (auth: {service.auth.type.value})"
        if service.auth.type != AuthType.NONE
        else ""
    )
    logger.info(
        f"  [{service.name}] Fetching OpenAPI spec from: {service.openapi_url}{auth_info}"
    )

    try:
        spec = await fetch_openapi_spec(service.openapi_url, service)
        api_title = spec.get("info", {}).get("title", "Unknown API")
        logger.info(f"  [{service.name}] Found: {api_title}")

        # Store the spec for schema merging
        state.service_openapi_specs[service.name] = spec

        route_count = register_routes_from_openapi(
            app,
            spec,
            service,
            service_configs,
            http_client,
            service_security_schemes,
            route_security_requirements,
            route_callbacks,
        )
        service_info["status"] = "active"
        service_info["routes"] = route_count
        service_info["api_title"] = api_title

        # Include extracted security schemes info
        if service.name in service_security_schemes:
            schemes = service_security_schemes[service.name]
            service_info["security_schemes"] = list(schemes.get("schemes", {}).keys())
            service_info["oauth2_scopes"] = schemes.get("scopes", {})

        logger.info(f"  [{service.name}] Registered {route_count} routes")
    except httpx.RequestError as e:
        service_info["status"] = "error"
        service_info["error"] = f"Failed to fetch OpenAPI spec: {e}"
        logger.error(
            f"  [{service.name}] ERROR: {service_info['error']}", exc_info=True
        )
    except Exception as e:
        service_info["status"] = "error"
        service_info["error"] = f"Unexpected error: {e}"
        logger.error(
            f"  [{service.name}] ERROR: {service_info['error']}", exc_info=True
        )

    return service_info
