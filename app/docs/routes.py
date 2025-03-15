from flask import jsonify, current_app
import json
import os
from apispec import APISpec
from apispec.ext.marshmallow import MarshmallowPlugin
from app.docs import docs_bp
from app.schemas import (
    DomainCheckResponseSchema,
    ErrorResponseSchema,
    MetricsResponseSchema,
    BulkCheckRequestSchema
)

def save_openapi_spec(spec: dict, filepath: str = "openapi.json") -> None:
    """Save OpenAPI specification to a file"""
    try:
        with open(filepath, 'w') as f:
            json.dump(spec, f, indent=2)
    except Exception as e:
        current_app.logger.error(f"Error saving OpenAPI spec to {filepath}: {str(e)}")

def generate_openapi_spec() -> dict:
    """Generate OpenAPI specification"""
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
                    }
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
                                            "items": {"$ref": "#/components/schemas/DomainCheckResponse"}
                                        }
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
                    }
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
    try:
        # Try to read from file first
        if os.path.exists('openapi.json'):
            with open('openapi.json', 'r') as f:
                return jsonify(json.load(f))
        # Fall back to generating on the fly
        return jsonify(generate_openapi_spec())
    except Exception as e:
        current_app.logger.error(f"Error serving OpenAPI spec: {str(e)}")
        return {"error": "Failed to generate API documentation"}, 500

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