"""Unit tests for validation and the raw WHOIS/DNS lookup handling."""
import socket
import time
from datetime import datetime
from types import SimpleNamespace

import pytest
from whois.exceptions import WhoisDomainNotFoundError, WhoisQuotaExceededError

import app.core.domain as domain_mod
from app.core.domain import (
    check_dns,
    check_whois,
    clean_domain_input,
    is_valid_domain_name,
    is_valid_tld,
    overall_status,
)


@pytest.mark.parametrize("name", ["a", "ab", "a-b", "123", "xn--bcher-kva", "a" * 63])
def test_valid_domain_names(name):
    assert is_valid_domain_name(name)


@pytest.mark.parametrize("name", ["", "-a", "a-", "a--b", "a.b", "a_b", "a" * 64, None, 5])
def test_invalid_domain_names(name):
    assert not is_valid_domain_name(name)


@pytest.mark.parametrize("tld", ["com", "io", ".org", "xn--p1ai"])
def test_valid_tlds(tld):
    assert is_valid_tld(tld)


@pytest.mark.parametrize("tld", ["", "a", "c0m", "co.uk", None])
def test_invalid_tlds(tld):
    assert not is_valid_tld(tld)


def test_clean_domain_input_defaults_to_com():
    assert clean_domain_input(" Example ", None) == ("example", "com", None)


def test_clean_domain_input_rejects_non_strings():
    assert clean_domain_input({"domain": "x"}, None)[2] == "Invalid domain name format"
    assert clean_domain_input("example", 42)[2] == "Invalid TLD format"


@pytest.mark.parametrize(
    "whois_status, dns_status, expected",
    [
        ("taken", "available", "taken"),
        ("available", "taken", "taken"),
        ("timeout", "taken", "taken"),
        ("available", "available", "available"),
        ("available", "error", "available"),
        ("available", "timeout", "available"),
        ("error", "available", "unknown"),
        ("timeout", "available", "unknown"),
        ("timeout", "timeout", "unknown"),
    ],
)
def test_overall_status(whois_status, dns_status, expected):
    assert overall_status({"status": whois_status}, {"status": dns_status}) == expected


# --------------------------------------------------------------------------- #
# WHOIS
# --------------------------------------------------------------------------- #

def _whois_returns(monkeypatch, value=None, raises=None):
    def fake(domain, **kwargs):
        if raises:
            raise raises
        return value

    monkeypatch.setattr(domain_mod.whois, "whois", fake)


def test_whois_not_found_means_available(monkeypatch):
    """Regression: this path used to raise AttributeError and return HTTP 500."""
    _whois_returns(monkeypatch, raises=WhoisDomainNotFoundError("No match"))
    assert domain_mod._whois_lookup("free.com") == {"status": "available"}


def test_whois_other_errors_are_errors_not_available(monkeypatch):
    _whois_returns(monkeypatch, raises=WhoisQuotaExceededError("quota"))
    assert domain_mod._whois_lookup("x.com")["status"] == "error"


def test_whois_taken_formats_fields(monkeypatch):
    entry = SimpleNamespace(
        domain_name="GOOGLE.COM",
        expiration_date=[datetime(2028, 9, 14, 4, 0), datetime(2028, 9, 13)],
        registrar=["MarkMonitor, Inc."],
        text="Domain Name: GOOGLE.COM",
    )
    _whois_returns(monkeypatch, entry)
    assert domain_mod._whois_lookup("google.com") == {
        "status": "taken",
        "expiration_date": "2028-09-14",
        "registrar": "MarkMonitor, Inc.",
    }


def test_whois_string_expiration_date_does_not_crash(monkeypatch):
    entry = SimpleNamespace(domain_name="X.IO", expiration_date="2030-01-01T00:00:00Z", registrar=None, text="x")
    _whois_returns(monkeypatch, entry)
    assert domain_mod._whois_lookup("x.io")["expiration_date"] == "2030-01-01T00:00:00Z"


@pytest.mark.parametrize(
    "text, status",
    [
        ("Socket not responding: timed out", "timeout"),
        ("Socket not responding: [Errno 61] Connection refused", "error"),
        ("", "error"),
    ],
)
def test_whois_server_failure_is_not_available(monkeypatch, text, status):
    """python-whois turns socket errors into response text; that isn't 'available'."""
    _whois_returns(monkeypatch, SimpleNamespace(domain_name=None, text=text))
    assert domain_mod._whois_lookup("x.com")["status"] == status


def test_check_whois_timeout_returns_dict(monkeypatch):
    """Regression: the timeout path used to return the bare string 'timeout'."""
    monkeypatch.setattr(domain_mod, "_whois_lookup", lambda d, t: time.sleep(0.5) or {"status": "available"})
    result = check_whois("slow.com", timeout=0.05)
    assert result == {"status": "timeout", "error": "WHOIS lookup timed out"}


# --------------------------------------------------------------------------- #
# DNS
# --------------------------------------------------------------------------- #

def _getaddrinfo_raises(monkeypatch, code):
    def fake(*args, **kwargs):
        raise socket.gaierror(code, "boom")

    monkeypatch.setattr(domain_mod.socket, "getaddrinfo", fake)


def test_dns_nxdomain_means_available(monkeypatch):
    _getaddrinfo_raises(monkeypatch, socket.EAI_NONAME)
    assert domain_mod._dns_lookup("free.com") == {"status": "available"}


def test_dns_resolver_failure_is_error(monkeypatch):
    _getaddrinfo_raises(monkeypatch, socket.EAI_AGAIN)
    assert domain_mod._dns_lookup("x.com")["status"] == "error"


def test_dns_prefers_ipv4(monkeypatch):
    infos = [
        (socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("2001:db8::1", 0, 0, 0)),
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("192.0.2.1", 0)),
    ]
    monkeypatch.setattr(domain_mod.socket, "getaddrinfo", lambda *a, **k: infos)
    assert domain_mod._dns_lookup("x.com") == {"status": "taken", "ip": "192.0.2.1"}


def test_dns_ipv6_only_is_taken(monkeypatch):
    infos = [(socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("2001:db8::1", 0, 0, 0))]
    monkeypatch.setattr(domain_mod.socket, "getaddrinfo", lambda *a, **k: infos)
    assert domain_mod._dns_lookup("x.com") == {"status": "taken", "ip": "2001:db8::1"}


def test_dns_queries_absolute_name(monkeypatch):
    """A trailing dot stops the resolver from trying the host's search domains."""
    seen = []

    def fake(host, *args, **kwargs):
        seen.append(host)
        raise socket.gaierror(socket.EAI_NONAME, "nope")

    monkeypatch.setattr(domain_mod.socket, "getaddrinfo", fake)
    domain_mod._dns_lookup("example.com")
    domain_mod._dns_lookup("example.com.")
    assert seen == ["example.com.", "example.com."]


@pytest.mark.parametrize(
    "raw, expected",
    [(None, 32), ("", 32), ("64", 64), (" 8 ", 8), ("abc", 32), ("0", 32), ("-4", 32)],
)
def test_lookup_workers_from_env(monkeypatch, raw, expected):
    if raw is None:
        monkeypatch.delenv("LOOKUP_WORKERS", raising=False)
    else:
        monkeypatch.setenv("LOOKUP_WORKERS", raw)
    assert domain_mod.lookup_workers_from_env() == expected


def test_check_dns_timeout_returns_dict(monkeypatch):
    monkeypatch.setattr(domain_mod, "_dns_lookup", lambda d: time.sleep(0.5) or {"status": "available"})
    assert check_dns("slow.com", timeout=0.05)["status"] == "timeout"
