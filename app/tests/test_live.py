"""Smoke tests against real WHOIS/DNS servers. Run with: pytest -m network"""
import uuid

import pytest

from app import create_app

pytestmark = pytest.mark.network


@pytest.fixture
def live_client():
    return create_app({"TESTING": True, "RATELIMIT_ENABLED": False, "CACHE_TYPE": "NullCache"}).test_client()


def test_registered_domain_is_taken(live_client):
    data = live_client.get("/?domain=google").get_json()
    assert data["status"] == "taken"
    assert data["whois"]["status"] == "taken"
    assert data["dns"]["status"] == "taken"


def test_unregistered_domain_is_available(live_client):
    """Regression: every available domain used to return HTTP 500."""
    name = f"zz-{uuid.uuid4().hex[:20]}"
    response = live_client.get(f"/?domain={name}")
    assert response.status_code == 200
    data = response.get_json()
    assert data["dns"]["status"] == "available"
    if data["whois"]["status"] == "available":
        assert data["status"] == "available"
    else:  # WHOIS server flaked: must not claim the domain is free
        assert data["status"] == "unknown"
