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
        servers=[{"url": "https://domains.fiodel.com", "description": "Production server"}]
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

@docs_bp.route('/docs')
def docs():
    return f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Domain Check API - Documentation</title>
        <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/swagger-ui-dist@5/swagger-ui.css">
        <link rel="icon" type="image/png" href="https://swagger.io/favicon.png">
    </head>
    <body>
        <div id="swagger-ui"></div>
        <script src="https://cdn.jsdelivr.net/npm/swagger-ui-dist@5/swagger-ui-bundle.js"></script>
        <script>
            window.onload = function() {{
                SwaggerUIBundle({{
                    url: '/openapi.json',
                    dom_id: '#swagger-ui',
                    deepLinking: true,
                    presets: [
                        SwaggerUIBundle.presets.apis,
                        SwaggerUIBundle.SwaggerUIStandalonePreset
                    ],
                }});
            }}
        </script>
    </body>
    </html>
    """
