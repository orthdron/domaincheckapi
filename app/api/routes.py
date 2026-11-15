import time
from typing import Any

from flask import current_app, jsonify, request

from app import cache, limiter
from app.api import api_bp
from app.core.domain import check_domains, clean_domain_input, is_cacheable

_CACHE_PREFIX = "domain:"


def _single_limit() -> str:
    return f"{current_app.config['RATE_LIMIT_SINGLE']} per minute"


def _bulk_limit() -> str:
    return f"{current_app.config['RATE_LIMIT_BULK']} per minute"


def _daily_limit() -> str:
    return f"{current_app.config['RATE_LIMIT_DAILY']} per day"


# One daily budget per client, shared by both check endpoints.
_daily = limiter.shared_limit(_daily_limit, scope="domain-checks")


def _metrics():
    return current_app.extensions["domaincheck_metrics"]


def _bad_request(message: str):
    return jsonify({"error": "Invalid request", "message": message}), 400


def _lookup(domains: list[str]) -> dict[str, dict[str, Any]]:
    """Resolve fully-qualified domains via cache, then live lookups for the misses."""
    keys = [_CACHE_PREFIX + d for d in domains]
    try:
        cached = dict(zip(domains, cache.get_many(*keys)))
    except Exception as exc:  # noqa: BLE001 -- a cache outage must not take the API down
        current_app.logger.warning("Cache read failed: %s", exc)
        cached = dict.fromkeys(domains)

    misses = [d for d, hit in cached.items() if hit is None]
    _metrics().incr("cache_hits", len(cached) - len(misses))
    _metrics().incr("cache_misses", len(misses))

    fresh = check_domains(
        misses,
        whois_timeout=current_app.config["WHOIS_TIMEOUT"],
        dns_timeout=current_app.config["DNS_TIMEOUT"],
    ) if misses else {}

    to_cache = {_CACHE_PREFIX + d: r for d, r in fresh.items() if is_cacheable(r)}
    if to_cache:
        try:
            cache.set_many(to_cache)
        except Exception as exc:  # noqa: BLE001
            current_app.logger.warning("Cache write failed: %s", exc)

    results = {}
    for domain in domains:
        hit = cached.get(domain)
        results[domain] = {**hit, "cached": True} if hit is not None else {**fresh[domain], "cached": False}
    return results


@api_bp.route("/", methods=["GET"])
@limiter.limit(_single_limit)
@_daily
def check_domain():
    start_time = time.perf_counter()

    domain_name, tld, error = clean_domain_input(request.args.get("domain"), request.args.get("tld"))
    if error:
        return _bad_request(error)

    full_domain = f"{domain_name}.{tld}"
    result = _lookup([full_domain])[full_domain]
    result["response_time"] = f"{time.perf_counter() - start_time:.2f}s"
    return jsonify(result)


@api_bp.route("/health", methods=["GET"])
@limiter.exempt
def health_check():
    """Simple health check endpoint"""
    return jsonify({"status": "ok"})


@api_bp.route("/metrics", methods=["GET"])
@limiter.exempt
def get_metrics():
    """Process-local API metrics."""
    metrics = _metrics()
    uptime = int(time.time() - metrics.started_at)
    days, rem = divmod(uptime, 86400)
    hours, rem = divmod(rem, 3600)
    minutes = rem // 60
    config = current_app.config
    return jsonify({
        "uptime": f"{days}d {hours}h {minutes}m",
        "uptime_seconds": uptime,
        "cache_stats": metrics.snapshot(),
        "rate_limits": {
            "enabled": bool(config["RATELIMIT_ENABLED"]),
            "single": _single_limit(),
            "bulk": _bulk_limit(),
            "daily": _daily_limit(),
        },
    })


@api_bp.route("/bulk", methods=["POST"])
@limiter.limit(_bulk_limit)
@_daily
def bulk_check():
    """Check multiple domains at once.

    ``domains`` may contain plain names (``"example"``, using the top-level ``tld``)
    or objects (``{"domain": "example", "tld": "org"}``).
    """
    start_time = time.perf_counter()

    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return _bad_request("Request body must be a JSON object")

    domains = data.get("domains")
    default_tld = data.get("tld")
    max_domains = current_app.config["MAX_BULK_DOMAINS"]

    if not isinstance(domains, list):
        return _bad_request("'domains' must be a list")
    if not domains:
        return _bad_request("'domains' must not be empty")
    if len(domains) > max_domains:
        return _bad_request(f"Maximum {max_domains} domains per request")

    # Validate everything first so all lookups can run concurrently.
    entries: list[tuple[str, str | None]] = []  # (full_domain or raw input, error)
    for item in domains:
        if isinstance(item, dict):
            raw_name, raw_tld = item.get("domain"), item.get("tld")
            if raw_tld is None:
                raw_tld = default_tld
        else:
            raw_name, raw_tld = item, default_tld
        domain_name, tld, error = clean_domain_input(raw_name, raw_tld)
        if error:
            label = raw_name if isinstance(raw_name, str) else repr(raw_name)
            if isinstance(raw_tld, str) and raw_tld:
                label = f"{label}.{raw_tld.lstrip('.')}"
            entries.append((label, error))
        else:
            entries.append((f"{domain_name}.{tld}", None))

    valid = list(dict.fromkeys(d for d, err in entries if err is None))
    found = _lookup(valid) if valid else {}

    response_time = f"{time.perf_counter() - start_time:.2f}s"
    results = [
        {"domain": d, "status": "error", "error": err}
        if err
        else {**found[d], "response_time": response_time}
        for d, err in entries
    ]
    return jsonify({"results": results, "response_time": response_time})
