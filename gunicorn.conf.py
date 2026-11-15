"""Gunicorn settings, picked up automatically from the working directory."""
import os

bind = f"0.0.0.0:{os.environ.get('PORT', '3000')}"

# Lookups are network-bound, so threads give concurrency cheaply. One worker by
# default keeps the in-memory cache and rate limits consistent; raise
# WEB_CONCURRENCY only when CACHE_TYPE=redis and REDIS_URL are configured.
workers = int(os.environ.get("WEB_CONCURRENCY", "1"))
worker_class = "gthread"
threads = int(os.environ.get("GUNICORN_THREADS", "16"))

# A bulk request is bounded by the WHOIS/DNS timeouts, well under this.
timeout = int(os.environ.get("GUNICORN_TIMEOUT", "30"))
graceful_timeout = 10
accesslog = "-"

# Gunicorn 27's runtime control socket isn't needed in a container.
control_socket_disable = True
