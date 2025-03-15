from flask import Flask, request, jsonify
import socket
import whois
import os
import re
import time
from functools import wraps
from datetime import datetime, timedelta
import threading
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_caching import Cache
import concurrent.futures
import logging
from logging.config import dictConfig
from flask_swagger_ui import get_swaggerui_blueprint
from docs import create_docs_endpoints
from schemas import DomainCheckResponseSchema, ErrorResponseSchema

app = Flask(__name__)

# Configure rate limiting if enabled
ENABLE_RATE_LIMITS = os.environ.get('ENABLE_RATE_LIMITS', 'false').lower() == 'true'

# Configure rate limiter storage
REDIS_URL = os.environ.get('REDIS_URL')
if ENABLE_RATE_LIMITS:
    if REDIS_URL:
        limiter = Limiter(
            app=app,
            key_func=get_remote_address,
            storage_uri=REDIS_URL,
            default_limits=["100 per day", "10 per minute"]
        )
    else:
        # Use memory storage with a warning in logs
        app.logger.warning(
            "Using in-memory storage for rate limiting. This is not recommended for production. "
            "Set REDIS_URL environment variable to use Redis storage."
        )
        limiter = Limiter(
            app=app,
            key_func=get_remote_address,
            storage_uri="memory://",
            default_limits=["100 per day", "10 per minute"]
        )
else:
    # Create a dummy limiter that doesn't actually limit
    class DummyLimiter:
        def limit(self, *args, **kwargs):
            def decorator(f):
                @wraps(f)
                def wrapped(*args, **kwargs):
                    return f(*args, **kwargs)
                return wrapped
            return decorator
        def exempt(self, f):
            @wraps(f)
            def wrapped(*args, **kwargs):
                return f(*args, **kwargs)
            return wrapped
    limiter = DummyLimiter()

# Configure caching
CACHE_TYPE = os.environ.get('CACHE_TYPE', 'simple')
CACHE_REDIS_URL = os.environ.get('CACHE_REDIS_URL')

cache_config = {
    'CACHE_TYPE': CACHE_TYPE,
    'CACHE_DEFAULT_TIMEOUT': int(os.environ.get('CACHE_TIMEOUT', 300))
}

if CACHE_TYPE == 'redis' and CACHE_REDIS_URL:
    cache_config['CACHE_REDIS_URL'] = CACHE_REDIS_URL

cache = Cache(app, config=cache_config)

# Timeout settings
WHOIS_TIMEOUT = int(os.environ.get('WHOIS_TIMEOUT', 5))  # seconds
DNS_TIMEOUT = int(os.environ.get('DNS_TIMEOUT', 3))      # seconds

# Initialize application state
app.config["start_time"] = datetime.utcnow().isoformat()

dictConfig({
    'version': 1,
    'formatters': {'default': {
        'format': '[%(asctime)s] %(levelname)s in %(module)s: %(message)s',
    }},
    'handlers': {'wsgi': {
        'class': 'logging.StreamHandler',
        'stream': 'ext://sys.stdout',
        'formatter': 'default'
    }},
    'root': {
        'level': os.getenv('LOG_LEVEL', 'INFO'),
        'handlers': ['wsgi']
    }
})

def is_valid_domain_name(domain):
    """Validate domain name format."""
    if not domain or not isinstance(domain, str):
        return False
        
    # Clean input
    domain = domain.strip().lower()
    
    # Basic validation
    if not domain or len(domain) > 63:
        return False
        
    # Check for invalid characters first
    if re.search(r'[^a-z0-9-]', domain):
        return False
        
    # Must start and end with alphanumeric
    if domain.startswith('-') or domain.endswith('-'):
        return False
        
    # Check for consecutive hyphens
    if '--' in domain:
        return False
        
    # Final regex check for overall format
    return bool(re.match(r'^[a-z0-9][a-z0-9-]*[a-z0-9]$', domain))

def is_valid_tld(tld):
    """Validate TLD format."""
    if not tld or not isinstance(tld, str):
        return False
        
    # Clean input
    tld = tld.strip().lstrip('.').lower()
    
    # Basic validation
    if not tld or len(tld) < 2:
        return False
        
    # Check for invalid characters first
    if re.search(r'[^a-z]', tld):
        return False
        
    # Final regex check for overall format
    return bool(re.match(r'^[a-z]{2,}$', tld))

def clean_domain_input(domain_name, tld):
    """Clean and validate domain input."""
    if not domain_name:
        return None, None, "Missing domain parameter"
        
    # Clean inputs
    domain_name = domain_name.strip().lower()
    tld = (tld or "com").strip().lstrip('.').lower()
    
    # Validate domain name
    if not is_valid_domain_name(domain_name):
        return None, None, "Invalid domain name format"
        
    # Validate TLD
    if not is_valid_tld(tld):
        return None, None, "Invalid TLD format"
        
    return domain_name, tld, None

def with_timeout(timeout):
    """Decorator to add timeout to functions."""
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            result = {"status": "error", "error": "Timeout"}
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
                future = executor.submit(func, *args, **kwargs)
                try:
                    result = future.result(timeout=timeout)
                except concurrent.futures.TimeoutError:
                    return "timeout"
                except Exception as e:
                    app.logger.error(f"Error in {func.__name__}: {str(e)}")
                    return "error"
            return result
        return wrapper
    return decorator

@with_timeout(WHOIS_TIMEOUT)
def check_whois(domain):
    """Check WHOIS for domain availability."""
    try:
        w = whois.whois(domain)
        if w.domain_name:
            expiration_date = w.expiration_date
            if isinstance(expiration_date, list):
                expiration_date = expiration_date[0]
            return {
                "status": "taken",
                "expiration_date": expiration_date.strftime("%Y-%m-%d") if expiration_date else None,
                "registrar": w.registrar
            }
        return {"status": "available"}
    except whois.parser.PywhoisError:
        return {"status": "available"}
    except Exception as e:
        app.logger.error(f"WHOIS error for domain {domain}: {str(e)}")
        return {"status": "error", "error": str(e)}

@with_timeout(DNS_TIMEOUT)
def check_dns(domain):
    """Check DNS resolution for domain availability."""
    try:
        ip = socket.gethostbyname(domain)
        return {"status": "taken", "ip": ip}
    except socket.gaierror:
        return {"status": "available"}
    except Exception as e:
        app.logger.error(f"DNS error for domain {domain}: {str(e)}")
        return {"status": "error", "error": str(e)}

@app.route("/", methods=["GET"])
@limiter.limit("10 per minute")
def check_domain():
    """Check domain availability.
    ---
    get:
      summary: Check domain availability
      parameters:
        - name: domain
          in: query
          required: true
          schema:
            type: string
        - name: tld
          in: query
          schema:
            type: string
            default: com
      responses:
        200:
          description: Domain check successful
          content:
            application/json:
              schema: DomainCheckResponseSchema
        400:
          description: Invalid request
          content:
            application/json:
              schema: ErrorResponseSchema
    """
    start_time = time.time()
    
    # Get domain parameter
    domain_name = request.args.get("domain", "").strip()
    if not domain_name:
        return jsonify({"error": "Missing domain parameter"}), 400
        
    # Get and validate TLD parameter
    tld = request.args.get("tld", "com").strip().lstrip('.').lower()
    if not is_valid_tld(tld):
        return jsonify({"error": "Invalid TLD format"}), 400
        
    # Clean and validate domain name
    domain_name = domain_name.strip().lower()
    if not is_valid_domain_name(domain_name):
        return jsonify({"error": "Invalid domain name format"}), 400
    
    # Generate cache key from normalized inputs
    cache_key = f"domain_check:{domain_name}:{tld}"
    
    # Try to get from cache
    cached_result = cache.get(cache_key)
    if cached_result is not None:
        cached_result['response_time'] = f"{(time.time() - start_time):.2f}s"
        cached_result['cached'] = True
        return jsonify(cached_result)
    
    # Construct full domain
    full_domain = f"{domain_name}.{tld}"
    
    # Check availability
    whois_result = check_whois(full_domain)
    dns_result = check_dns(full_domain)
    
    # Determine overall status
    status = "taken" if (whois_result.get("status") == "taken" or 
                        dns_result.get("status") == "taken") else "available"
    
    response = {
        "domain": full_domain,
        "status": status,
        "whois": whois_result,
        "dns": dns_result,
        "tld": tld,
        "response_time": f"{(time.time() - start_time):.2f}s",
        "cached": False
    }
    
    # Cache the response
    cache.set(cache_key, response, timeout=300)
    
    return jsonify(response)

@app.route("/health", methods=["GET"])
@limiter.exempt
def health_check():
    """Health check endpoint."""
    return jsonify({
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat(),
        "version": "1.0.0",
        "rate_limiting": {
            "enabled": ENABLE_RATE_LIMITS,
            "storage": "redis" if REDIS_URL else "memory"
        },
        "cache": {
            "type": CACHE_TYPE,
            "timeout": cache_config['CACHE_DEFAULT_TIMEOUT']
        },
        "timeouts": {
            "whois": f"{WHOIS_TIMEOUT}s",
            "dns": f"{DNS_TIMEOUT}s"
        }
    })

@app.route("/metrics", methods=["GET"])
@limiter.exempt
def metrics():
    """Basic metrics endpoint."""
    return jsonify({
        "cache_stats": {
            "cache_hits": cache.get("cache_hits") or 0,
            "cache_misses": cache.get("cache_misses") or 0
        },
        "uptime": app.config.get("start_time", datetime.utcnow().isoformat()),
        "rate_limiting_enabled": ENABLE_RATE_LIMITS
    })

@app.route("/bulk", methods=["POST"])
@limiter.limit("5 per minute")
def bulk_check():
    """Bulk domain checking endpoint."""
    if not request.is_json:
        return jsonify({"error": "Request must be JSON"}), 400

    domains = request.json.get("domains")
    if not domains or not isinstance(domains, list):
        return jsonify({"error": "Invalid or missing domains list"}), 400
    
    max_domains = int(os.environ.get('MAX_BULK_DOMAINS', 10))
    if len(domains) > max_domains:
        return jsonify({"error": f"Too many domains. Maximum is {max_domains} per request"}), 400

    results = {}
    errors = []
    
    for domain in domains:
        if not isinstance(domain, dict):
            errors.append(f"Invalid domain entry: {domain}")
            continue
            
        name = domain.get("domain", "").strip()
        if not name:
            errors.append("Missing domain name")
            continue
            
        tld = domain.get("tld", "com").strip().lstrip('.').lower()
        if not is_valid_tld(tld):
            errors.append(f"Invalid TLD: {tld}")
            continue
            
        name = name.strip().lower()
        if not is_valid_domain_name(name):
            errors.append(f"Invalid domain name: {name}")
            continue

        # Generate cache key
        cache_key = f"domain_check:{name}:{tld}"
        
        # Try to get from cache first
        cached_result = cache.get(cache_key)
        if cached_result is not None:
            cached_result['cached'] = True
            results[f"{name}.{tld}"] = cached_result
            continue

        # If not in cache, check domain
        full_domain = f"{name}.{tld}"
        whois_result = check_whois(full_domain)
        dns_result = check_dns(full_domain)
        
        status = "taken" if (whois_result.get("status") == "taken" or 
                           dns_result.get("status") == "taken") else "available"
        
        response = {
            "domain": full_domain,
            "status": status,
            "whois": whois_result,
            "dns": dns_result,
            "tld": tld,
            "cached": False
        }
        
        # Cache the result
        cache.set(cache_key, response, timeout=300)
        results[full_domain] = response

    if not results and errors:
        return jsonify({
            "error": "No valid domains provided",
            "details": errors
        }), 400

    return jsonify({
        "results": results,
        "errors": errors if errors else None
    })

@app.errorhandler(Exception)
def handle_exception(e):
    """Handle all uncaught exceptions."""
    app.logger.error(f"Unhandled exception: {str(e)}", exc_info=True)
    return jsonify({
        "error": "Internal server error",
        "message": str(e) if app.debug else "An unexpected error occurred"
    }), 500

# Add Swagger UI
SWAGGER_URL = '/docs'
API_URL = '/static/openapi.yaml'

swaggerui_blueprint = get_swaggerui_blueprint(
    SWAGGER_URL,
    API_URL,
    config={
        'app_name': "Domain Check API"
    }
)
app.register_blueprint(swaggerui_blueprint)

# Add documentation endpoints
create_docs_endpoints(app)

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 3000))
    app.run(host="0.0.0.0", port=port)
