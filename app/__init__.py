from flask import Flask
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_caching import Cache
import os

# Initialize extensions
limiter = Limiter(key_func=get_remote_address)
cache = Cache()

def create_app():
    """Application factory function"""
    app = Flask(__name__)

    # Configure rate limiting
    ENABLE_RATE_LIMITS = os.environ.get('ENABLE_RATE_LIMITS', 'false').lower() == 'true'
    REDIS_URL = os.environ.get('REDIS_URL')
    
    if ENABLE_RATE_LIMITS:
        if REDIS_URL:
            limiter.storage_uri = REDIS_URL
            app.logger.info("Rate limiting enabled with Redis storage")
        else:
            app.logger.warning(
                "Using in-memory storage for rate limiting. This is not recommended for production. "
                "Set REDIS_URL environment variable to use Redis storage."
            )
            limiter.storage_uri = "memory://"
    else:
        # When rate limiting is disabled, set a very high limit
        limiter.storage_uri = "memory://"
        app.logger.info("Rate limiting is disabled")
        
        # Override the limit decorator to be a no-op
        def limit_exempt(f):
            return f
        limiter.limit = lambda *args, **kwargs: limit_exempt

    limiter.init_app(app)

    # Configure caching
    cache_config = {
        'CACHE_TYPE': os.environ.get('CACHE_TYPE', 'simple'),
        'CACHE_DEFAULT_TIMEOUT': int(os.environ.get('CACHE_TIMEOUT', 300))
    }

    if cache_config['CACHE_TYPE'] == 'redis':
        CACHE_REDIS_URL = os.environ.get('CACHE_REDIS_URL')
        if CACHE_REDIS_URL:
            cache_config['CACHE_REDIS_URL'] = CACHE_REDIS_URL

    cache.init_app(app, config=cache_config)

    # Register blueprints
    from app.api import api_bp
    from app.docs import docs_bp
    
    app.register_blueprint(api_bp)
    app.register_blueprint(docs_bp)

    return app 