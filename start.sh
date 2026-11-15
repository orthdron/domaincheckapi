#!/usr/bin/env bash
# Local convenience script: create a venv, install dependencies, run gunicorn.
set -euo pipefail
cd "$(dirname "$0")"

if [ ! -d ".venv" ]; then
    echo "Creating virtual environment..."
    python3 -m venv .venv
fi
source .venv/bin/activate

echo "Installing dependencies..."
pip install -q -r requirements.txt

echo "Starting application on port ${PORT:-3000}..."
exec gunicorn wsgi:app
