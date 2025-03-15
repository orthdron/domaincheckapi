from apispec import APISpec
from apispec.ext.marshmallow import MarshmallowPlugin
from apispec_webframeworks.flask import FlaskPlugin
from flask import Flask, jsonify
from schemas import *

def generate_openapi_spec(app: Flask) -> dict:
    """Generate OpenAPI specification from Flask app"""
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
        plugins=[FlaskPlugin(), MarshmallowPlugin()],
    )

    # Add schemas
    spec.components.schema("DomainCheckResponse", schema=DomainCheckResponseSchema)
    spec.components.schema("ErrorResponse", schema=ErrorResponseSchema)
    spec.components.schema("MetricsResponse", schema=MetricsResponseSchema)
    spec.components.schema("BulkCheckRequest", schema=BulkCheckRequestSchema)

    # Add paths
    with app.test_request_context():
        spec.path(
            path="/",
            operations={
                "get": {
                    "summary": "Check domain availability",
                    "parameters": [
                        {
                            "name": "domain",
                            "in": "query",
                            "required": True,
                            "schema": {"type": "string"}
                        },
                        {
                            "name": "tld",
                            "in": "query",
                            "schema": {"type": "string", "default": "com"}
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
            }
        )

    return spec.to_dict()

def create_docs_endpoints(app: Flask):
    """Add documentation endpoints to Flask app"""
    
    @app.route('/openapi.json')
    def openapi_spec():
        return jsonify(generate_openapi_spec(app))

    @app.route('/docs')
    def docs():
        return f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Domain Check API - Documentation</title>
            <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/swagger-ui-dist@5/swagger-ui.css">
        </head>
        <body>
            <div id="swagger-ui"></div>
            <script src="https://cdn.jsdelivr.net/npm/swagger-ui-dist@5/swagger-ui-bundle.js"></script>
            <script>
                window.onload = function() {{
                    SwaggerUIBundle({{
                        url: '/openapi.json',
                        dom_id: '#swagger-ui',
                    }});
                }}
            </script>
        </body>
        </html>
        """ 