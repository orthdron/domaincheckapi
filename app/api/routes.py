from flask import request, jsonify
from datetime import datetime, timedelta
import concurrent.futures
import time
from app import limiter, cache
from app.core.domain import check_whois, check_dns, is_valid_domain_name, is_valid_tld, clean_domain_input
from app.api import api_bp
from app.schemas import DomainCheckResponseSchema, ErrorResponseSchema

@api_bp.route("/", methods=["GET"])
@limiter.limit("10 per minute")
def check_domain():
    start_time = time.time()
    
    # Get domain parameter
    domain_name = request.args.get('domain', '').strip()
    tld = request.args.get('tld', 'com').strip()
    
    # Clean and validate input
    domain_name, tld, error = clean_domain_input(domain_name, tld)
    if error:
        return jsonify({"error": "Invalid request", "message": error}), 400
        
    # Form full domain
    full_domain = f"{domain_name}.{tld}"
    
    # Check cache
    cached_result = cache.get(full_domain)
    if cached_result:
        cached_result['cached'] = True
        return jsonify(cached_result)
    
    # Check domain availability
    whois_result = check_whois(full_domain)
    dns_result = check_dns(full_domain)
    
    # Determine overall status
    status = "taken" if whois_result.get("status") == "taken" or dns_result.get("status") == "taken" else "available"
    
    # Prepare response
    response = {
        "domain": full_domain,
        "status": status,
        "whois": whois_result,
        "dns": dns_result,
        "tld": tld,
        "response_time": f"{time.time() - start_time:.2f}s",
        "cached": False
    }
    
    # Cache result
    cache.set(full_domain, response)
    
    return jsonify(response)

@api_bp.route("/health", methods=["GET"])
@limiter.exempt
def health_check():
    """Simple health check endpoint"""
    return jsonify({"status": "ok"})

@api_bp.route("/metrics", methods=["GET"])
@limiter.exempt
def get_metrics():
    """Get API metrics"""
    start_time = datetime.fromisoformat(api_bp.config["start_time"])
    uptime = datetime.utcnow() - start_time
    
    days = uptime.days
    hours = uptime.seconds // 3600
    minutes = (uptime.seconds % 3600) // 60
    
    uptime_str = f"{days}d {hours}h {minutes}m"
    
    # Get cache stats if available
    cache_stats = {}
    if hasattr(cache, 'get_stats'):
        cache_stats = cache.get_stats()
    
    # Get rate limit info if available
    rate_limits = {}
    if hasattr(limiter, 'get_limits'):
        rate_limits = limiter.get_limits()
    
    return jsonify({
        "uptime": uptime_str,
        "cache_stats": cache_stats,
        "rate_limits": rate_limits
    })

@api_bp.route("/bulk", methods=["POST"])
@limiter.limit("5 per minute")
def bulk_check():
    """Check multiple domains at once"""
    data = request.get_json()
    
    if not data or not isinstance(data, dict):
        return jsonify({"error": "Invalid request", "message": "Request body must be JSON"}), 400
        
    domains = data.get('domains', [])
    tld = data.get('tld', 'com')
    
    if not isinstance(domains, list):
        return jsonify({"error": "Invalid request", "message": "Domains must be a list"}), 400
        
    if len(domains) > 10:  # Limit number of domains
        return jsonify({"error": "Invalid request", "message": "Maximum 10 domains per request"}), 400
    
    results = []
    for domain in domains:
        domain_name, tld_clean, error = clean_domain_input(domain, tld)
        if error:
            results.append({
                "domain": f"{domain}.{tld}",
                "status": "error",
                "error": error
            })
            continue
            
        full_domain = f"{domain_name}.{tld_clean}"
        
        # Check cache
        cached_result = cache.get(full_domain)
        if cached_result:
            cached_result['cached'] = True
            results.append(cached_result)
            continue
        
        # Check domain
        whois_result = check_whois(full_domain)
        dns_result = check_dns(full_domain)
        
        status = "taken" if whois_result.get("status") == "taken" or dns_result.get("status") == "taken" else "available"
        
        result = {
            "domain": full_domain,
            "status": status,
            "whois": whois_result,
            "dns": dns_result,
            "tld": tld_clean,
            "cached": False
        }
        
        cache.set(full_domain, result)
        results.append(result)
    
    return jsonify({"results": results}) 