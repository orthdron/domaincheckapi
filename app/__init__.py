import logging
import os
import threading
import time
from typing import Any, Optional

from flask import Flask, jsonify
from flask_caching import Cache
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.exceptions import HTTPException

logger = logging.getLogger(__name__)

# Initialize extensions
limiter = Limiter(key_func=get_remote_address)
cache = Cache()

# Short names accepted in CACHE_TYPE -> Flask-Caching backend classes.
_CACHE_BACKENDS = {"simple": "SimpleCache", "redis": "RedisCache", "null": "NullCache"}


def _env_str(name: str) -> Optional[str]:
    value = os.environ.get(name, "").strip()
    return value or None


def _env_bool(name: str, default: bool = False) -> bool:
    value = _env_str(name)
    return default if value is None else value.lower() in ("1", "true", "yes", "on")


def _env_number(name: str, default: Any, cast=int):
    value = _env_str(name)
    if value is None:
        return default
    try:
        return cast(value)
    except ValueError:
        logger.warning("Ignoring invalid %s=%r, using default %r", name, value, default)
        return default


class Metrics:
    """Process-local counters for /metrics (per gunicorn worker)."""

    def __init__(self) -> None:
        self.started_at = time.time()
        self._lock = threading.Lock()
        self._counts = {"cache_hits": 0, "cache_misses": 0}

    def incr(self, name: str, amount: int = 1) -> None:
        if amount:
            with self._lock:
                self._counts[name] += amount

    def snapshot(self) -> dict[str, int]:
        with self._lock:
            return dict(self._counts)


def load_config() -> dict[str, Any]:
    """Build app config from environment variables (see example.env)."""
    cache_type = _env_str("CACHE_TYPE") or "simple"
    return {
        # Lookups
        "WHOIS_TIMEOUT": _env_number("WHOIS_TIMEOUT", 5.0, float),
        "DNS_TIMEOUT": _env_number("DNS_TIMEOUT", 3.0, float),
        "MAX_BULK_DOMAINS": _env_number("MAX_BULK_DOMAINS", 10),
        # Rate limiting (Flask-Limiter reads the RATELIMIT_* keys)
        "RATELIMIT_ENABLED": _env_bool("ENABLE_RATE_LIMITS", False),
        "RATELIMIT_STORAGE_URI": _env_str("REDIS_URL") or "memory://",
        "RATELIMIT_HEADERS_ENABLED": True,
        "RATE_LIMIT_SINGLE": _env_number("RATE_LIMIT_SINGLE", 10),
        "RATE_LIMIT_BULK": _env_number("RATE_LIMIT_BULK", 5),
        "RATE_LIMIT_DAILY": _env_number("RATE_LIMIT_DAILY", 100),
        # Caching
        "CACHE_TYPE": _CACHE_BACKENDS.get(cache_type.lower(), cache_type),
        "CACHE_DEFAULT_TIMEOUT": _env_number("CACHE_TIMEOUT", 300),
        "CACHE_REDIS_URL": _env_str("CACHE_REDIS_URL"),
        # Number of reverse proxies in front of the app (Railway, Dokploy, nginx...).
        # Needed for per-client rate limiting; leave 0 when exposed directly.
        "TRUSTED_PROXY_COUNT": _env_number("TRUSTED_PROXY_COUNT", 0),
    }


def create_app(config: Optional[dict[str, Any]] = None) -> Flask:
    """Application factory. ``config`` overrides values read from the environment."""
    app = Flask(__name__)
    app.config.update(load_config())
    if config:
        app.config.update(config)

    if app.config["TRUSTED_PROXY_COUNT"] > 0:
        from werkzeug.middleware.proxy_fix import ProxyFix

        hops = app.config["TRUSTED_PROXY_COUNT"]
        app.wsgi_app = ProxyFix(app.wsgi_app, x_for=hops, x_proto=hops, x_host=hops)

    if app.config["RATELIMIT_ENABLED"]:
        if app.config["RATELIMIT_STORAGE_URI"].startswith("memory://"):
            app.logger.warning(
                "Rate limiting uses in-memory storage (per process, lost on restart). "
                "Set REDIS_URL for production."
            )
        else:
            app.logger.info("Rate limiting enabled with external storage")
    else:
        app.logger.info("Rate limiting is disabled")

    limiter.init_app(app)
    cache.init_app(app)
    app.extensions["domaincheck_metrics"] = Metrics()

    @app.errorhandler(HTTPException)
    def handle_http_error(exc: HTTPException):
        """Return JSON instead of HTML for 404/405/415/429/500 etc."""
        return jsonify(error=exc.name, message=exc.description), exc.code

    # Register blueprints
    from app.api import api_bp
    from app.docs import docs_bp

    app.register_blueprint(api_bp)
    app.register_blueprint(docs_bp)

    return app
