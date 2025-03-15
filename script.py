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

app = Flask(__name__)

# Configure rate limiting if enabled
ENABLE_RATE_LIMITS = os.environ.get('ENABLE_RATE_LIMITS', 'true').lower() == 'true'

if ENABLE_RATE_LIMITS:
    limiter = Limiter(
        app=app,
        key_func=get_remote_address,
        default_limits=["100 per day", "10 per minute"]
    )
else:
    # Create a dummy limiter that doesn't actually limit
    class DummyLimiter:
        def limit(self, *args, **kwargs):
            def decorator(f):
                return f
            return decorator
        def exempt(self, f):
            return f
    limiter = DummyLimiter()

# Configure caching
cache = Cache(app, config={
    'CACHE_TYPE': 'simple',
    'CACHE_DEFAULT_TIMEOUT': 300  # Cache results for 5 minutes
})

# Timeout settings
WHOIS_TIMEOUT = int(os.environ.get('WHOIS_TIMEOUT', 5))  # seconds
DNS_TIMEOUT = int(os.environ.get('DNS_TIMEOUT', 3))      # seconds

def is_valid_domain_name(domain):
    """Validate domain name format."""
    pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$'
    return bool(re.match(pattern, domain))

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
@cache.memoize(timeout=300)
def check_domain():
    """API Endpoint to check domain availability."""
    start_time = time.time()
    
    domain_name = request.args.get("domain")
    tld = request.args.get("tld", "com").lstrip(".")
    
    if not domain_name:
        return jsonify({"error": "Missing domain parameter"}), 400
    
    if not isinstance(domain_name, str):
        return jsonify({"error": "Invalid domain parameter"}), 400

    # Remove any TLD if included in the domain parameter
    domain_name = domain_name.split('.')[0]

    # Validate domain name format
    if not is_valid_domain_name(domain_name):
        return jsonify({"error": "Invalid domain name format"}), 400

    # Validate TLD format
    if not re.match(r'^[a-zA-Z]{2,}$', tld):
        return jsonify({"error": "Invalid TLD format"}), 400

    # Construct full domain
    full_domain = f"{domain_name}.{tld}"

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
        "response_time": f"{(time.time() - start_time):.2f}s"
    }

    return jsonify(response)

@app.route("/health", methods=["GET"])
@limiter.exempt
def health_check():
    """Health check endpoint."""
    return jsonify({
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat(),
        "version": "1.0.0",
        "rate_limiting": ENABLE_RATE_LIMITS,
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
    domains = request.json.get("domains", [])
    if not domains or not isinstance(domains, list):
        return jsonify({"error": "Invalid or missing domains list"}), 400
    
    if len(domains) > 10:  # Limit bulk requests to 10 domains
        return jsonify({"error": "Too many domains. Maximum is 10 per request"}), 400

    results = {}
    for domain in domains:
        name = domain.get("domain")
        tld = domain.get("tld", "com")
        if name:
            with app.test_request_context(f"/?domain={name}&tld={tld}"):
                results[f"{name}.{tld}"] = check_domain().json

    return jsonify(results)

@app.before_first_request
def before_first_request():
    """Initialize application state."""
    app.config["start_time"] = datetime.utcnow().isoformat()

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)
