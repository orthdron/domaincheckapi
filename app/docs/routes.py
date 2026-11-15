import json
import logging
from functools import cache

from apispec import APISpec
from apispec.ext.marshmallow import MarshmallowPlugin
from flask import jsonify

from app.docs import docs_bp
from app.schemas import (
    BulkCheckRequestSchema,
    BulkErrorItemSchema,
    DomainCheckResponseSchema,
    ErrorResponseSchema,
    MetricsResponseSchema,
)

logger = logging.getLogger(__name__)


def save_openapi_spec(spec: dict, filepath: str = "openapi.json") -> None:
    """Write the OpenAPI specification to a file (used to refresh openapi.json)."""
    with open(filepath, "w") as f:
        json.dump(spec, f, indent=2)
        f.write("\n")
    logger.info("Wrote OpenAPI spec to %s", filepath)


@cache
def generate_openapi_spec() -> dict:
    """Generate the OpenAPI specification (built once per process)."""
    spec = APISpec(
        title="Domain Check API",
        version="1.0.0",
        openapi_version="3.0.3",
        info=dict(
            description="API for checking domain availability using WHOIS and DNS lookups",
            license=dict(
                name="MIT",
                url="https://opensource.org/licenses/MIT"
            ),
            contact=dict(
                name="Deepak Kapoor",
                url="https://github.com/orthdron/domaincheckapi"
            )
        ),
        plugins=[MarshmallowPlugin()],
        servers=[
            # Relative first, so "Try it out" hits whichever server is showing the docs.
            {"url": "/", "description": "This server"},
            {"url": "https://domains.fiodel.com", "description": "Production server"},
        ]
    )

    # Add schemas
    spec.components.schema("DomainCheckResponse", schema=DomainCheckResponseSchema)
    spec.components.schema("ErrorResponse", schema=ErrorResponseSchema)
    spec.components.schema("MetricsResponse", schema=MetricsResponseSchema)
    spec.components.schema("BulkCheckRequest", schema=BulkCheckRequestSchema)
    spec.components.schema("BulkErrorItem", schema=BulkErrorItemSchema)

    rate_limited = {
        "description": "Rate limit exceeded (only when ENABLE_RATE_LIMITS=true)",
        "content": {
            "application/json": {"schema": {"$ref": "#/components/schemas/ErrorResponse"}}
        },
    }

    # Add paths
    paths = {
        "/": {
            "get": {
                "tags": ["Domain Check"],
                "summary": "Check domain availability",
                "description": "Check availability of a single domain using WHOIS and DNS",
                "parameters": [
                    {
                        "name": "domain",
                        "in": "query",
                        "required": True,
                        "schema": {"type": "string"},
                        "description": "Domain name to check (without TLD)"
                    },
                    {
                        "name": "tld",
                        "in": "query",
                        "schema": {"type": "string", "default": "com"},
                        "description": "Top-level domain (e.g., com, net, org)"
                    }
                ],
                "responses": {
                    "200": {
                        "description": "Domain check successful",
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/DomainCheckResponse"}
                            }
                        }
                    },
                    "400": {
                        "description": "Invalid request",
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/ErrorResponse"}
                            }
                        }
                    },
                    "429": rate_limited
                }
            }
        },
        "/health": {
            "get": {
                "tags": ["System"],
                "summary": "Health check",
                "description": "Check if the API is running",
                "responses": {
                    "200": {
                        "description": "API is healthy",
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "properties": {
                                        "status": {"type": "string", "example": "ok"}
                                    }
                                }
                            }
                        }
                    }
                }
            }
        },
        "/metrics": {
            "get": {
                "tags": ["System"],
                "summary": "Get API metrics",
                "description": "Get current API metrics including uptime and cache stats",
                "responses": {
                    "200": {
                        "description": "Metrics retrieved successfully",
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/MetricsResponse"}
                            }
                        }
                    }
                }
            }
        },
        "/bulk": {
            "post": {
                "tags": ["Domain Check"],
                "summary": "Bulk domain check",
                "description": "Check availability of multiple domains at once",
                "requestBody": {
                    "required": True,
                    "content": {
                        "application/json": {
                            "schema": {"$ref": "#/components/schemas/BulkCheckRequest"}
                        }
                    }
                },
                "responses": {
                    "200": {
                        "description": "Bulk check successful",
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "properties": {
                                        "results": {
                                            "type": "array",
                                            "items": {
                                                "oneOf": [
                                                    {"$ref": "#/components/schemas/DomainCheckResponse"},
                                                    {"$ref": "#/components/schemas/BulkErrorItem"}
                                                ]
                                            }
                                        },
                                        "response_time": {"type": "string", "example": "1.20s"}
                                    }
                                }
                            }
                        }
                    },
                    "400": {
                        "description": "Invalid request",
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/ErrorResponse"}
                            }
                        }
                    },
                    "429": rate_limited
                }
            }
        }
    }

    # Add paths to spec
    for path, operations in paths.items():
        spec.path(path=path, operations=operations)

    return spec.to_dict()

@docs_bp.route('/openapi.json')
def openapi_spec():
    # Served from code so it can never drift from the running API.
    return jsonify(generate_openapi_spec())

# Pinned Swagger UI with Subresource Integrity, so a CDN or npm compromise can't
# change what /docs runs. To upgrade: bump the version and recompute both hashes
# (openssl dgst -sha384 -binary FILE | openssl base64 -A).
SWAGGER_UI_VERSION = "5.34.1"
_SWAGGER_UI_CDN = f"https://cdn.jsdelivr.net/npm/swagger-ui-dist@{SWAGGER_UI_VERSION}"
_SWAGGER_UI_CSS_SRI = "sha384-4c3vsE5f+trhFyHrFrLM1fFGUn531NIaC7dcqEWIJdoRQJ5CkJbSuSCwXLpaS1KF"
_SWAGGER_UI_JS_SRI = "sha384-XFYN47VzPiDY6qPtxYKg0nqUeW/upo20xf1j2SUE7gT/i35FJB4cuS/71Iegzk8Z"

DOCS_HTML = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Domain Check API - Documentation</title>
    <link rel="stylesheet" href="{_SWAGGER_UI_CDN}/swagger-ui.css"
          integrity="{_SWAGGER_UI_CSS_SRI}" crossorigin="anonymous">
    <link rel="icon" type="image/png" href="https://swagger.io/favicon.png">
</head>
<body>
    <div id="swagger-ui"></div>
    <script src="{_SWAGGER_UI_CDN}/swagger-ui-bundle.js"
            integrity="{_SWAGGER_UI_JS_SRI}" crossorigin="anonymous"></script>
    <script>
        window.onload = function() {{
            SwaggerUIBundle({{
                url: '/openapi.json',
                dom_id: '#swagger-ui',
                deepLinking: true,
                presets: [SwaggerUIBundle.presets.apis],
            }});
        }};
    </script>
</body>
</html>
"""


@docs_bp.route('/docs')
def docs():
    return DOCS_HTML
