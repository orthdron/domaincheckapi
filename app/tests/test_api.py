import json
import time
from pathlib import Path

import pytest

from app.docs.routes import SWAGGER_UI_VERSION, generate_openapi_spec

REPO_ROOT = Path(__file__).resolve().parents[2]


# --------------------------------------------------------------------------- #
# System endpoints
# --------------------------------------------------------------------------- #

def test_health_check(client):
    response = client.get("/health")
    assert response.status_code == 200
    assert response.get_json() == {"status": "ok"}


def test_metrics_counts_cache_hits_and_misses(client):
    client.get("/?domain=google")
    client.get("/?domain=google")

    response = client.get("/metrics")
    assert response.status_code == 200
    data = response.get_json()
    assert data["cache_stats"] == {"cache_hits": 1, "cache_misses": 1}
    assert data["uptime"].endswith("m")
    assert isinstance(data["uptime_seconds"], int)
    assert data["rate_limits"] == {
        "enabled": False,
        "single": "10 per minute",
        "bulk": "5 per minute",
        "daily": "100 per day",
    }


def test_unknown_route_returns_json(client):
    response = client.get("/nope")
    assert response.status_code == 404
    assert response.get_json()["error"] == "Not Found"


# --------------------------------------------------------------------------- #
# Single domain check
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("name", ["google", "facebook"])
def test_known_domains_are_taken(client, name):
    data = client.get(f"/?domain={name}").get_json()
    assert data["domain"] == f"{name}.com"
    assert data["status"] == "taken"
    assert data["whois"]["status"] == "taken"
    assert data["whois"]["registrar"] == "MarkMonitor, Inc."
    assert data["dns"]["status"] == "taken"
    assert data["tld"] == "com"
    assert data["cached"] is False
    assert data["response_time"].endswith("s")


def test_available_domain(client):
    response = client.get("/?domain=zqxv-unregistered-9f3k")
    assert response.status_code == 200
    data = response.get_json()
    assert data["status"] == "available"
    assert data["whois"] == {"status": "available"}
    assert data["dns"] == {"status": "available"}


def test_custom_tld(client):
    data = client.get("/?domain=google&tld=org").get_json()
    assert data["domain"] == "google.org"
    assert data["tld"] == "org"


def test_input_is_normalised(client):
    data = client.get("/?domain=%20Google%20&tld=.COM").get_json()
    assert data["domain"] == "google.com"


@pytest.mark.parametrize("domain", ["x", "a1", "xn--bcher-kva", "my-site"])
def test_valid_edge_case_domains(client, domain):
    assert client.get(f"/?domain={domain}").status_code == 200


@pytest.mark.parametrize(
    "domain",
    ["inv@lid", "-invalid", "invalid-", "inv--alid", "a" * 64, "", " ", "domain.with.dots"],
)
def test_invalid_domain(client, domain):
    response = client.get(f"/?domain={domain}")
    assert response.status_code == 400
    data = response.get_json()
    assert data["error"] == "Invalid request"
    assert data["message"]


@pytest.mark.parametrize("tld", ["123", "a", "com@", "", " ", "com.", "co.uk"])
def test_invalid_tld(client, tld):
    response = client.get(f"/?domain=example&tld={tld}")
    assert response.status_code == 400
    assert response.get_json()["message"] == "Invalid TLD format"


def test_missing_domain(client):
    response = client.get("/")
    assert response.status_code == 400
    assert response.get_json()["message"] == "Missing domain parameter"


def test_results_are_cached(client, lookups):
    first = client.get("/?domain=google").get_json()
    second = client.get("/?domain=google").get_json()
    assert first["cached"] is False
    assert second["cached"] is True
    assert second["status"] == "taken"
    assert lookups.count("whois") == 1


def test_failed_lookups_are_not_cached(client, lookups):
    lookups.whois_override = lambda d: {"status": "timeout", "error": "WHOIS lookup timed out"}
    client.get("/?domain=flaky")
    second = client.get("/?domain=flaky").get_json()
    assert second["status"] == "unknown"
    assert second["cached"] is False
    assert lookups.count("whois") == 2


def test_dns_hit_is_taken_even_if_whois_fails(client, lookups):
    lookups.whois_override = lambda d: {"status": "error", "error": "boom"}
    assert client.get("/?domain=google").get_json()["status"] == "taken"


def test_slow_whois_is_cut_off_at_timeout(make_app, lookups):
    def slow(domain):
        time.sleep(1.0)
        return {"status": "available"}

    lookups.whois_override = slow
    client = make_app(WHOIS_TIMEOUT=0.2).test_client()

    started = time.perf_counter()
    response = client.get("/?domain=slowpoke")
    elapsed = time.perf_counter() - started

    assert response.status_code == 200
    data = response.get_json()
    assert data["status"] == "unknown"
    assert data["whois"]["status"] == "timeout"
    assert data["dns"]["status"] == "available"
    assert elapsed < 0.8


# --------------------------------------------------------------------------- #
# Bulk check
# --------------------------------------------------------------------------- #

def test_bulk_check_with_names(client):
    response = client.post("/bulk", json={"domains": ["google", "facebook"], "tld": "com"})
    assert response.status_code == 200
    results = response.get_json()["results"]
    assert [r["domain"] for r in results] == ["google.com", "facebook.com"]
    assert all(r["status"] == "taken" for r in results)
    assert all(r["whois"]["status"] == "taken" and r["dns"]["status"] == "taken" for r in results)


def test_bulk_check_with_objects(client):
    """The object form documented in the README used to crash with a 500."""
    payload = {
        "domains": [
            {"domain": "google", "tld": "com"},
            {"domain": "google", "tld": "org"},
            {"domain": "example"},
            "facebook",
        ],
        "tld": "com",
    }
    response = client.post("/bulk", json=payload)
    assert response.status_code == 200
    results = response.get_json()["results"]
    assert [r["domain"] for r in results] == ["google.com", "google.org", "example.com", "facebook.com"]
    assert [r["status"] for r in results] == ["taken", "taken", "available", "taken"]


def test_bulk_check_with_invalid_domains(client):
    payload = {"domains": ["google", "inv@lid", "-invalid", "", 42, {"tld": "com"}]}
    results = client.post("/bulk", json=payload).get_json()["results"]
    assert len(results) == 6
    assert results[0]["domain"] == "google.com"
    assert results[0]["status"] == "taken"
    assert [r["status"] for r in results[1:]] == ["error"] * 5
    assert all(r["error"] for r in results[1:])


def test_bulk_deduplicates_lookups(client, lookups):
    results = client.post("/bulk", json={"domains": ["google", "google", "GOOGLE"]}).get_json()["results"]
    assert len(results) == 3
    assert lookups.count("whois") == 1


def test_bulk_lookups_run_concurrently(make_app, lookups):
    def slow(domain):
        time.sleep(0.3)
        return {"status": "available"}

    lookups.whois_override = slow
    lookups.dns_override = slow
    client = make_app().test_client()

    started = time.perf_counter()
    response = client.post("/bulk", json={"domains": [f"site{i}" for i in range(5)]})
    elapsed = time.perf_counter() - started

    assert response.status_code == 200
    assert len(response.get_json()["results"]) == 5
    assert elapsed < 1.0  # 10 sequential lookups would take 3s


@pytest.mark.parametrize(
    "kwargs, message",
    [
        ({"json": {}}, "'domains' must be a list"),
        ({"json": {"domains": "not a list"}}, "'domains' must be a list"),
        ({"json": {"domains": []}}, "'domains' must not be empty"),
        ({"json": {"domains": ["test"] * 11}}, "Maximum 10 domains per request"),
        ({"json": ["google"]}, "Request body must be a JSON object"),
        ({"data": "not json", "content_type": "text/plain"}, "Request body must be a JSON object"),
        ({"data": "{broken", "content_type": "application/json"}, "Request body must be a JSON object"),
    ],
)
def test_bulk_check_invalid_request(client, kwargs, message):
    response = client.post("/bulk", **kwargs)
    assert response.status_code == 400
    assert response.get_json()["message"] == message


def test_bulk_limit_is_configurable(make_app, lookups):
    client = make_app(MAX_BULK_DOMAINS=2).test_client()
    response = client.post("/bulk", json={"domains": ["a", "b", "c"]})
    assert response.status_code == 400
    assert response.get_json()["message"] == "Maximum 2 domains per request"


# --------------------------------------------------------------------------- #
# Rate limiting
# --------------------------------------------------------------------------- #

def test_rate_limits_are_enforced_when_enabled(make_app, lookups):
    client = make_app(RATELIMIT_ENABLED=True, RATE_LIMIT_SINGLE=2).test_client()
    assert client.get("/?domain=google").status_code == 200
    assert client.get("/?domain=google").status_code == 200

    response = client.get("/?domain=google")
    assert response.status_code == 429
    assert response.get_json()["error"] == "Too Many Requests"

    # Exempt endpoints keep working.
    assert client.get("/health").status_code == 200
    assert client.get("/metrics").status_code == 200


def test_daily_limit_is_shared_across_endpoints(make_app, lookups):
    client = make_app(RATELIMIT_ENABLED=True, RATE_LIMIT_DAILY=2).test_client()
    assert client.get("/?domain=google").status_code == 200
    assert client.post("/bulk", json={"domains": ["google"]}).status_code == 200
    assert client.get("/?domain=google").status_code == 429


def test_rate_limits_still_apply_when_store_is_down(make_app, lookups):
    """With Redis unreachable, checks keep working (no 500s) and limits still hold."""
    app = make_app(
        RATELIMIT_ENABLED=True,
        RATELIMIT_STORAGE_URI="redis://127.0.0.1:1",
        RATE_LIMIT_SINGLE=2,
    )
    client = app.test_client()

    first = client.get("/?domain=google")
    assert first.status_code == 200
    assert first.get_json()["status"] == "taken"
    assert client.get("/?domain=google").status_code == 200
    assert client.get("/?domain=google").status_code == 429


def test_rate_limits_are_off_by_default(client):
    for _ in range(15):
        assert client.get("/?domain=google").status_code == 200


# --------------------------------------------------------------------------- #
# Docs
# --------------------------------------------------------------------------- #

def test_openapi_endpoint(client):
    spec = client.get("/openapi.json").get_json()
    assert spec["info"]["title"] == "Domain Check API"
    assert {"/", "/bulk", "/health", "/metrics"} <= set(spec["paths"])
    # "Try it out" must target the server showing the docs, not production.
    assert spec["servers"][0]["url"] == "/"


def test_committed_openapi_json_is_up_to_date():
    committed = json.loads((REPO_ROOT / "openapi.json").read_text())
    assert committed == generate_openapi_spec(), (
        "openapi.json is stale; regenerate with: python -m app.docs"
    )


def test_docs_page_pins_swagger_ui_with_integrity(client):
    response = client.get("/docs")
    assert response.status_code == 200
    html = response.get_data(as_text=True)
    assert f"swagger-ui-dist@{SWAGGER_UI_VERSION}/" in html
    assert "swagger-ui-dist@5/" not in html
    assert html.count('integrity="sha384-') == 2
    assert html.count('crossorigin="anonymous"') == 2
