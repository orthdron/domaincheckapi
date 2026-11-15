import pytest

import app.core.domain as domain_mod
from app import create_app

REGISTERED = {"google.com", "facebook.com", "google.org"}

_ENV_VARS = (
    "ENABLE_RATE_LIMITS", "REDIS_URL", "CACHE_TYPE", "CACHE_REDIS_URL", "CACHE_TIMEOUT",
    "WHOIS_TIMEOUT", "DNS_TIMEOUT", "MAX_BULK_DOMAINS", "RATE_LIMIT_SINGLE",
    "RATE_LIMIT_BULK", "RATE_LIMIT_DAILY", "TRUSTED_PROXY_COUNT",
)


class FakeLookups:
    """Stand-in for the real WHOIS/DNS lookups; records every call."""

    def __init__(self):
        self.calls = []
        self.whois_override = None
        self.dns_override = None

    def whois(self, domain, timeout=5.0):
        self.calls.append(("whois", domain))
        if self.whois_override:
            return self.whois_override(domain)
        if domain in REGISTERED:
            return {"status": "taken", "expiration_date": "2028-09-14", "registrar": "MarkMonitor, Inc."}
        return {"status": "available"}

    def dns(self, domain):
        self.calls.append(("dns", domain))
        if self.dns_override:
            return self.dns_override(domain)
        if domain in REGISTERED:
            return {"status": "taken", "ip": "142.250.0.1"}
        return {"status": "available"}

    def count(self, kind):
        return sum(1 for k, _ in self.calls if k == kind)


@pytest.fixture
def lookups(monkeypatch):
    fake = FakeLookups()
    monkeypatch.setattr(domain_mod, "_whois_lookup", fake.whois)
    monkeypatch.setattr(domain_mod, "_dns_lookup", fake.dns)
    return fake


@pytest.fixture
def make_app(monkeypatch):
    for var in _ENV_VARS:
        monkeypatch.delenv(var, raising=False)

    def factory(**config):
        return create_app({"TESTING": True, "RATELIMIT_ENABLED": False, **config})

    return factory


@pytest.fixture
def client(make_app, lookups):
    return make_app().test_client()
