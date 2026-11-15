"""Domain validation and availability lookups (WHOIS + DNS)."""
from __future__ import annotations

import logging
import os
import re
import socket
import time
from concurrent.futures import Future, ThreadPoolExecutor
from concurrent.futures import TimeoutError as FutureTimeoutError
from datetime import date, datetime
from typing import Any, Callable, Iterable, Optional, Tuple

import whois
from whois.exceptions import WhoisDomainNotFoundError

logger = logging.getLogger(__name__)

DEFAULT_TLD = "com"
DEFAULT_WHOIS_TIMEOUT = 5.0
DEFAULT_DNS_TIMEOUT = 3.0

# Lookup statuses that mean "we could not find out" -- never cached.
FAILED_STATUSES = frozenset({"error", "timeout"})

# What python-whois puts in the response body when it swallows a socket error.
_WHOIS_SOCKET_ERROR_PREFIX = "Socket not responding"

_LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
_TLD_RE = re.compile(r"^(?:[a-z]{2,63}|xn--[a-z0-9-]{1,59})$")

# getaddrinfo error codes that mean "this name has no address records".
# Anything else (EAI_AGAIN, EAI_FAIL, ...) is a resolver failure, not an answer.
_DNS_NOT_FOUND_CODES = frozenset(
    code
    for code in (getattr(socket, "EAI_NONAME", None), getattr(socket, "EAI_NODATA", None))
    if code is not None
)

DEFAULT_LOOKUP_WORKERS = 32


def lookup_workers_from_env() -> int:
    """LOOKUP_WORKERS, falling back to the default (with a warning) if invalid."""
    raw = os.environ.get("LOOKUP_WORKERS", "").strip()
    if not raw:
        return DEFAULT_LOOKUP_WORKERS
    try:
        value = int(raw)
    except ValueError:
        value = 0
    if value < 1:
        logger.warning(
            "Ignoring invalid LOOKUP_WORKERS=%r, using default %d", raw, DEFAULT_LOOKUP_WORKERS
        )
        return DEFAULT_LOOKUP_WORKERS
    return value


# One shared pool for all lookups. WHOIS and DNS calls are blocking I/O and can't be
# cancelled once started, so a shared pool bounds the number of in-flight lookups
# instead of spawning (and then waiting on) a fresh pool per call.
_executor = ThreadPoolExecutor(
    max_workers=lookup_workers_from_env(),
    thread_name_prefix="domain-lookup",
)


# --------------------------------------------------------------------------- #
# Validation
# --------------------------------------------------------------------------- #

def is_valid_domain_name(domain: str) -> bool:
    """Validate a single domain label (the part before the TLD)."""
    if not isinstance(domain, str):
        return False
    domain = domain.strip().lower()
    if not _LABEL_RE.match(domain):
        return False
    # Consecutive hyphens are reserved for IDN (punycode) labels like "xn--bcher-kva".
    if "--" in domain and not domain.startswith("xn--"):
        return False
    return True


def is_valid_tld(tld: str) -> bool:
    """Validate TLD format (letters only, or a punycode IDN TLD)."""
    if not isinstance(tld, str):
        return False
    return bool(_TLD_RE.match(tld.strip().lstrip(".").lower()))


def clean_domain_input(
    domain_name: Any, tld: Any = None
) -> Tuple[Optional[str], Optional[str], Optional[str]]:
    """Normalise and validate input. Returns (domain, tld, error)."""
    if domain_name is None or (isinstance(domain_name, str) and not domain_name.strip()):
        return None, None, "Missing domain parameter"
    if not isinstance(domain_name, str):
        return None, None, "Invalid domain name format"

    domain_name = domain_name.strip().lower()

    if tld is None:
        tld = DEFAULT_TLD
    elif not isinstance(tld, str):
        return None, None, "Invalid TLD format"
    else:
        tld = tld.strip().lstrip(".").lower()

    if not is_valid_domain_name(domain_name):
        return None, None, "Invalid domain name format"
    if not is_valid_tld(tld):
        return None, None, "Invalid TLD format"

    return domain_name, tld, None


# --------------------------------------------------------------------------- #
# Raw lookups (blocking; run on the shared executor)
# --------------------------------------------------------------------------- #

def _format_date(value: Any) -> Optional[str]:
    if isinstance(value, list):
        value = value[0] if value else None
    if isinstance(value, (datetime, date)):
        return value.strftime("%Y-%m-%d")
    if value is None:
        return None
    return str(value)


def _whois_lookup(domain: str, timeout: float = DEFAULT_WHOIS_TIMEOUT) -> dict[str, Any]:
    # A lookup is usually two hops: registry, then a referral to the registrar's
    # server. Registrar servers are often slow; giving each socket half the budget
    # lets a stalled referral fail in time for the registry's answer to be used.
    socket_timeout = max(1.0, timeout / 2)
    try:
        w = whois.whois(domain, quiet=True, timeout=socket_timeout)
    except WhoisDomainNotFoundError:
        return {"status": "available"}
    except Exception as exc:  # noqa: BLE001 -- python-whois raises many types
        logger.warning("WHOIS lookup failed for %s: %s", domain, exc)
        return {"status": "error", "error": str(exc) or exc.__class__.__name__}

    if w.domain_name:
        registrar = w.registrar
        if isinstance(registrar, list):
            registrar = registrar[0] if registrar else None
        return {
            "status": "taken",
            "expiration_date": _format_date(w.expiration_date),
            "registrar": registrar,
        }

    # python-whois swallows socket errors and returns their message as the response
    # body. That parses to an entry with no domain_name, which must not be mistaken
    # for "available". (A failed registrar referral is fine: the registry's answer
    # is still in the text and parses as taken above.)
    text = (getattr(w, "text", "") or "").strip()
    if not text:
        return {"status": "error", "error": "Empty WHOIS response"}
    if text.startswith(_WHOIS_SOCKET_ERROR_PREFIX):
        status = "timeout" if "timed out" in text.lower() else "error"
        logger.warning("WHOIS server unreachable for %s: %s", domain, text)
        return {"status": status, "error": text}
    return {"status": "available"}


def _dns_lookup(domain: str) -> dict[str, Any]:
    try:
        # Trailing dot = absolute name, so the resolver never tries the host's search
        # domains (extra queries, and a wildcard there would look like "taken").
        infos = socket.getaddrinfo(domain.rstrip(".") + ".", None, proto=socket.IPPROTO_TCP)
    except socket.gaierror as exc:
        if exc.errno in _DNS_NOT_FOUND_CODES:
            return {"status": "available"}
        return {"status": "error", "error": str(exc)}
    except Exception as exc:  # noqa: BLE001
        return {"status": "error", "error": str(exc)}

    addresses = [info[4][0] for info in infos]
    if not addresses:
        return {"status": "available"}
    ipv4 = [a for a in addresses if ":" not in a]  # prefer IPv4 for the "ip" field
    return {"status": "taken", "ip": (ipv4 or addresses)[0]}


# --------------------------------------------------------------------------- #
# Timeout-bounded public API
# --------------------------------------------------------------------------- #

def _collect(future: Future, deadline: float, what: str) -> dict[str, Any]:
    try:
        return future.result(timeout=max(0.0, deadline - time.monotonic()))
    except FutureTimeoutError:
        future.cancel()  # frees the slot if the lookup never started
        return {"status": "timeout", "error": f"{what} lookup timed out"}
    except Exception as exc:  # noqa: BLE001 -- lookups catch their own errors
        return {"status": "error", "error": str(exc)}


def _run(fn: Callable[..., dict[str, Any]], *args: Any, timeout: float, what: str) -> dict[str, Any]:
    return _collect(_executor.submit(fn, *args), time.monotonic() + timeout, what)


def check_whois(domain: str, timeout: float = DEFAULT_WHOIS_TIMEOUT) -> dict[str, Any]:
    """WHOIS availability check, bounded by ``timeout`` seconds. Never raises."""
    return _run(_whois_lookup, domain, timeout, timeout=timeout, what="WHOIS")


def check_dns(domain: str, timeout: float = DEFAULT_DNS_TIMEOUT) -> dict[str, Any]:
    """DNS resolution check, bounded by ``timeout`` seconds. Never raises."""
    return _run(_dns_lookup, domain, timeout=timeout, what="DNS")


def overall_status(whois_result: dict[str, Any], dns_result: dict[str, Any]) -> str:
    """Combine both lookups into "taken", "available" or "unknown".

    Either lookup finding the domain is proof it's taken. Otherwise WHOIS is the
    authority: plenty of registered domains have no DNS records, so if WHOIS
    failed we can't call the domain available.
    """
    if whois_result.get("status") == "taken" or dns_result.get("status") == "taken":
        return "taken"
    if whois_result.get("status") in FAILED_STATUSES:
        return "unknown"
    return "available"


def is_cacheable(result: dict[str, Any]) -> bool:
    """Only cache definitive answers; a timeout or error should be retried."""
    return (
        result["whois"].get("status") not in FAILED_STATUSES
        and result["dns"].get("status") not in FAILED_STATUSES
    )


def check_domains(
    domains: Iterable[str],
    whois_timeout: float = DEFAULT_WHOIS_TIMEOUT,
    dns_timeout: float = DEFAULT_DNS_TIMEOUT,
) -> dict[str, dict[str, Any]]:
    """Check many fully-qualified domains concurrently.

    Every WHOIS and DNS lookup is started at once, so total latency is bounded by
    the slowest timeout rather than the sum of all lookups.
    """
    start = time.monotonic()
    pending = {
        domain: (
            _executor.submit(_whois_lookup, domain, whois_timeout),
            _executor.submit(_dns_lookup, domain),
        )
        for domain in dict.fromkeys(domains)  # de-duplicate, keep order
    }

    results: dict[str, dict[str, Any]] = {}
    for domain, (whois_future, dns_future) in pending.items():
        whois_result = _collect(whois_future, start + whois_timeout, "WHOIS")
        dns_result = _collect(dns_future, start + dns_timeout, "DNS")
        results[domain] = {
            "domain": domain,
            "status": overall_status(whois_result, dns_result),
            "whois": whois_result,
            "dns": dns_result,
            "tld": domain.rsplit(".", 1)[-1],
        }
    return results
