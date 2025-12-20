"""OpenAPI specification processing and extraction."""

from typing import Any

from fastapi import APIRouter



def extract_security_from_spec(
    spec: dict[str, Any],
    service_name: str,
) -> dict[str, Any]:
    """Extract security schemes and their scopes from an OpenAPI spec."""
    components = spec.get("components", {})
    security_schemes = components.get("securitySchemes", {})

    extracted = {
        "schemes": {},
        "scopes": {},
    }

    for scheme_name, scheme_def in security_schemes.items():
        prefixed_name = f"{service_name}_{scheme_name}"
        extracted["schemes"][prefixed_name] = scheme_def

        # Extract OAuth2 scopes
        if scheme_def.get("type") == "oauth2":
            flows = scheme_def.get("flows", {})
            all_scopes = {}
            for flow_name, flow_def in flows.items():
                if isinstance(flow_def, dict) and "scopes" in flow_def:
                    all_scopes.update(flow_def["scopes"])
            extracted["scopes"][prefixed_name] = all_scopes

    return extracted


def get_operation_security(
    operation: dict[str, Any],
    spec: dict[str, Any],
    service_name: str,
) -> list[dict[str, list[str]]]:
    """Get security requirements for an operation, prefixed with service name."""
    # Operation-level security overrides global
    security = operation.get("security")
    if security is None:
        security = spec.get("security", [])

    if not security:
        return []

    # Prefix security scheme names with service name
    prefixed_security = []
    for req in security:
        prefixed_req = {}
        for scheme_name, scopes in req.items():
            prefixed_req[f"{service_name}_{scheme_name}"] = scopes
        prefixed_security.append(prefixed_req)

    return prefixed_security


def resolve_callback_ref(ref: str, spec: dict[str, Any]) -> dict[str, Any] | None:
    """Resolve a $ref callback reference."""
    if ref.startswith("#/components/callbacks/"):
        callback_name = ref.split("/")[-1]
        components = spec.get("components", {})
        callbacks = components.get("callbacks", {})
        return callbacks.get(callback_name)
    return None


def create_callback_router(
    callbacks: dict[str, Any],
    spec: dict[str, Any],
    service_name: str,
) -> APIRouter | None:
    """Create an APIRouter from OpenAPI callback definitions.

    Callbacks structure in OpenAPI:
    {
      "callbackName": {
        "{$callback_url}/path": {
          "post": { ...operation... }
        }
      }
    }
    """
    if not callbacks:
        return None

    callback_router = APIRouter()
    http_methods = ["get", "post", "put", "patch", "delete", "options", "head"]

    def create_callback_handler(
        callback_path: str,
        callback_method: str,
        callback_operation: dict[str, Any],
    ):
        """Create a placeholder handler for a callback route."""

        def handler(*args, **kwargs):
            pass

        handler_name = (
            f"{service_name}_callback_{callback_method}_"
            f"{callback_path.replace('/', '_').replace('{', '').replace('}', '').replace('$', '')}"
        )
        handler.__name__ = handler_name
        return handler

    # Process each callback
    for callback_name, callback_path_item in callbacks.items():
        # Handle $ref references
        if isinstance(callback_path_item, dict) and "$ref" in callback_path_item:
            callback_path_item = resolve_callback_ref(callback_path_item["$ref"], spec)
            if not callback_path_item:
                continue

        # A callback path item is a dict where keys are paths (which may contain expressions)
        # and values are path item objects (dicts with HTTP methods)
        if not isinstance(callback_path_item, dict):
            continue

        for callback_path, path_item in callback_path_item.items():
            if not isinstance(path_item, dict):
                continue

            for method in http_methods:
                if method not in path_item:
                    continue

                callback_operation = path_item[method]
                if not isinstance(callback_operation, dict):
                    continue

                summary = callback_operation.get("summary", "")
                description = callback_operation.get("description", "")

                # Create the callback route
                # FastAPI will handle OpenAPI path expressions like {$callback_url}
                handler = create_callback_handler(
                    callback_path, method, callback_operation
                )
                handler.__doc__ = description or summary

                callback_router.add_api_route(
                    path=callback_path,
                    endpoint=handler,
                    methods=[method.upper()],
                    summary=summary,
                    description=description,
                )

    return callback_router if callback_router.routes else None


def extract_parameters_from_operation(
    operation: dict[str, Any],
    path_item: dict[str, Any],
    spec: dict[str, Any],
) -> dict[str, Any]:
    """Extract and resolve parameters from operation and path item."""
    # Parameters can be defined at both operation and path item level
    # Path item parameters apply to all operations
    operation_params = operation.get("parameters", [])
    path_item_params = path_item.get("parameters", [])

    # Combine parameters, operation-level overrides path-level
    all_params = {}
    for param in path_item_params + operation_params:
        if isinstance(param, dict):
            param_name = param.get("name")
            if param_name:
                all_params[param_name] = param
        elif isinstance(param, str) and param.startswith("#/"):
            # Handle $ref parameters
            ref_path = param.split("/")[1:]
            resolved = spec
            for part in ref_path:
                resolved = resolved.get(part, {})
            if isinstance(resolved, dict) and "name" in resolved:
                all_params[resolved["name"]] = resolved

    return all_params


def extract_request_body_schema(
    operation: dict[str, Any],
    spec: dict[str, Any],
) -> dict[str, Any] | None:
    """Extract request body schema from operation."""
    request_body = operation.get("requestBody")
    if not request_body:
        return None

    # Handle $ref
    if isinstance(request_body, dict) and "$ref" in request_body:
        ref_path = request_body["$ref"].split("/")[1:]
        resolved = spec
        for part in ref_path:
            resolved = resolved.get(part, {})
        request_body = resolved

    if not isinstance(request_body, dict):
        return None

    # Get content schemas
    content = request_body.get("content", {})
    schemas = {}
    for content_type, content_def in content.items():
        if isinstance(content_def, dict):
            schema = content_def.get("schema")
            if schema:
                schemas[content_type] = schema

    return (
        {"content": schemas, "required": request_body.get("required", False)}
        if schemas
        else None
    )


def extract_responses_schema(
    operation: dict[str, Any],
    spec: dict[str, Any],
) -> dict[str, Any]:
    """Extract response schemas from operation."""
    responses = operation.get("responses", {})
    if not responses:
        return {}

    response_schemas = {}
    for status_code, response_def in responses.items():
        if isinstance(response_def, dict) and "$ref" in response_def:
            # Handle $ref
            ref_path = response_def["$ref"].split("/")[1:]
            resolved = spec
            for part in ref_path:
                resolved = resolved.get(part, {})
            response_def = resolved

        if isinstance(response_def, dict):
            content = response_def.get("content", {})
            schemas = {}
            for content_type, content_def_item in content.items():
                if isinstance(content_def_item, dict):
                    schema = content_def_item.get("schema")
                    if schema:
                        schemas[content_type] = schema
            if schemas:
                response_schemas[status_code] = {
                    "description": response_def.get("description", ""),
                    "content": schemas,
                }

    return response_schemas


def build_openapi_extra(
    operation: dict[str, Any],
    path_item: dict[str, Any],
    spec: dict[str, Any],
) -> dict[str, Any]:
    """Build openapi_extra dict for proper OpenAPI documentation."""
    openapi_extra: dict[str, Any] = {}

    # Extract parameters
    parameters = extract_parameters_from_operation(operation, path_item, spec)
    if parameters:
        openapi_extra["parameters"] = list(parameters.values())

    # Extract request body
    request_body_schema = extract_request_body_schema(operation, spec)
    if request_body_schema:
        openapi_extra["requestBody"] = {
            "required": request_body_schema["required"],
            "content": {
                content_type: {"schema": schema}
                for content_type, schema in request_body_schema["content"].items()
            },
        }

    # Extract responses
    responses_schema = extract_responses_schema(operation, spec)
    if responses_schema:
        openapi_extra["responses"] = responses_schema

    return openapi_extra
