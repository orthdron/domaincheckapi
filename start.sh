#!/bin/bash

# Check if virtual environment exists
if [ ! -d ".venv" ]; then
    echo "Creating virtual environment..."
    python3 -m venv .venv
fi

# Activate virtual environment
source .venv/bin/activate

# Install dependencies
echo "Installing dependencies..."
pip install -r requirements.txt

# Generate OpenAPI spec
echo "Generating OpenAPI specification..."
python -c "from app.docs.routes import generate_openapi_spec, save_openapi_spec; save_openapi_spec(generate_openapi_spec())"

# Start the application
echo "Starting application..."
python wsgi.py 