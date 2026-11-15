"""Refresh the committed openapi.json:  python -m app.docs"""
import logging

from app.docs.routes import generate_openapi_spec, save_openapi_spec

logging.basicConfig(level=logging.INFO, format="%(message)s")
save_openapi_spec(generate_openapi_spec())
