# Dynamic API Gateway

A FastAPI-based dynamic API gateway that automatically generates routes from multiple remote OpenAPI specifications. This gateway acts as a unified entry point for multiple backend services, supporting OAuth2 scope validation, JWT authentication, and automatic route registration.

## Features

- **Dynamic Route Generation**: Automatically generates FastAPI routes from remote OpenAPI 2.0 and 3.0 specifications
- **Multi-Service Support**: Aggregate multiple backend services into a single gateway
- **OAuth2 Scope Validation**: Validates OAuth2 scopes from JWT tokens before forwarding requests
- **JWT Authentication**: Supports both HS256 and RS256 JWT algorithms
- **Gateway-Level Authentication**: Optional API key authentication at the gateway level
- **OpenAPI Schema Merging**: Automatically merges schemas from all registered services
- **Callback Support**: Preserves and exposes OpenAPI callbacks from backend services
- **Health Monitoring**: Built-in health check and service status endpoints
- **Security Scheme Propagation**: Automatically propagates security requirements to backend services

## Installation

### Prerequisites

- Python 3.14 or higher
- `uv` package manager (recommended) or `pip`

### Setup

1. Clone the repository:

```bash
git clone <repository-url>
cd fastapi-route-generation
```

1. Install dependencies using `uv`:

```bash
uv sync
```

Or using `pip`:

```bash
pip install -e .
```

## Configuration

### Services Configuration

Configure your backend services in `services.json`:

```json
[
  {
    "name": "my-service",
    "openapi_url": "https://api.example.com/openapi.json",
    "backend_base_url": "https://api.example.com",
    "prefix": "/my-service",
    "enabled": true,
    "auth": {
      "type": "oauth2",
      "token_url": "https://auth.example.com/oauth/token"
    },
    "propagate_security": true
  }
]
```

**Service Configuration Fields:**

- `name`: Unique identifier for the service
- `openapi_url`: URL to the OpenAPI specification (supports both 2.0 and 3.0)
- `backend_base_url`: Base URL for the backend service
- `prefix`: URL prefix for all routes from this service (e.g., `/my-service`)
- `enabled`: Whether the service is active
- `auth.type`: Authentication type (`none`, `oauth2`, `apiKey`, `http`)
- `propagate_security`: Whether to forward security headers/tokens to the backend

### Environment Variables

Create a `.env` file or set environment variables:

```bash
# Services configuration (JSON string or path to file)
SERVICES_CONFIG_FILE=services.json
# OR
SERVICES_CONFIG='[{"name": "service1", ...}]'

# Gateway authentication (optional)
GATEWAY_API_KEY=your-secret-key
GATEWAY_API_KEY_HEADER=X-Gateway-Key

# JWT validation (optional, for OAuth2 scope checking)
JWT_SECRET=your-jwt-secret  # For HS256
JWT_PUBLIC_KEY=your-public-key  # For RS256
JWT_ALGORITHMS=HS256,RS256
JWT_AUDIENCE=your-audience
JWT_ISSUER=your-issuer

# HTTP client settings
HTTP_TIMEOUT=30.0

# Logging
LOG_LEVEL=INFO
LOG_FORMAT=json  # or "text"
LOG_FILE=gateway.log  # optional
```

## Usage

### Running the Gateway

Start the gateway using `uvicorn`:

```bash
uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

Or using `uv`:

```bash
uv run uvicorn main:app --reload
```

The gateway will:

1. Load service configurations from `services.json` or environment variables
2. Fetch OpenAPI specifications from each service
3. Dynamically register routes for each service
4. Merge all OpenAPI schemas into a unified specification

### Accessing the API

- **API Documentation**: http://localhost:8000/docs (Swagger UI)
- **ReDoc Documentation**: http://localhost:8000/redoc
- **OpenAPI Schema**: http://localhost:8000/openapi.json
- **Gateway Info**: http://localhost:8000/ (requires gateway auth if enabled)
- **Health Check**: http://localhost:8000/health (no auth required)
- **Security Info**: http://localhost:8000/security (requires gateway auth)

## API Endpoints

### Gateway Endpoints

- `GET /` - Gateway status and service information (requires gateway auth if enabled)
- `GET /health` - Health check endpoint (no authentication required)
- `GET /security` - List all security schemes and route requirements (requires gateway auth)

### Service Routes

All service routes are automatically generated based on their OpenAPI specifications and are accessible under their configured prefix:

- `/my-service/path/to/endpoint` - Routes from services with prefix `/my-service`
- `/uspto/path/to/endpoint` - Routes from services with prefix `/uspto`

## Security

### Gateway Authentication

When `GATEWAY_API_KEY` is set, all gateway endpoints (except `/health`) require authentication via the configured header (default: `X-Gateway-Key`).

### OAuth2 Scope Validation

When JWT validation is enabled (`JWT_SECRET` or `JWT_PUBLIC_KEY`), the gateway:

1. Validates JWT tokens from `Authorization: Bearer <token>` headers
2. Extracts OAuth2 scopes from the token
3. Checks if the requested route requires specific scopes
4. Only forwards requests if the token has the required scopes

### Security Propagation

When `propagate_security: true` is set for a service, the gateway automatically forwards:

- Authorization headers
- API keys
- Other security-related headers to the backend service

## Architecture

```text
┌─────────────┐
│   Client    │
└──────┬──────┘
       │
       ▼
┌─────────────────────────────────┐
│     Dynamic API Gateway         │
│  ┌───────────────────────────┐  │
│  │  Route Registration       │  │
│  │  - Fetch OpenAPI specs    │  │
│  │  - Generate routes        │  │
│  │  - Merge schemas          │  │
│  └───────────────────────────┘  │
│  ┌───────────────────────────┐  │
│  │  Security Layer           │  │
│  │  - Gateway auth           │  │
│  │  - JWT validation         │  │
│  │  - Scope checking         │  │
│  └───────────────────────────┘  │
│  ┌───────────────────────────┐  │
│  │  Request Proxy            │  │
│  │  - Forward requests       │  │
│  │  - Propagate security     │  │
│  └───────────────────────────┘  │
└──────┬──────────────────────────┘
       │
       ├──────────┬──────────┬──────────┐
       ▼          ▼          ▼          ▼
   Service 1  Service 2  Service 3  Service N
```

## Development

### Project Structure

```
fastapi-route-generation/
├── app/
│   ├── __init__.py
│   ├── auth.py          # Authentication and authorization logic
│   ├── config.py        # Configuration management
│   ├── logging_config.py # Logging setup
│   ├── models.py        # Pydantic models
│   ├── openapi.py       # OpenAPI schema handling
│   ├── proxy.py         # Request proxying logic
│   ├── routes.py        # Route registration
│   └── state.py         # Application state
├── main.py              # FastAPI application entry point
├── services.json        # Service configurations
├── pyproject.toml       # Project dependencies
└── README.md
```