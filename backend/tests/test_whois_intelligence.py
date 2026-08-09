"""Tests for the WHOIS Intelligence Engine.

Rules are exercised at the intelligence-unit level (deterministic day values)
and end-to-end through ``run_whois_check`` with a stubbed registry lookup.
"""

import datetime
from dataclasses import dataclass
from typing import Any

from app.modules.whois.intelligence import evaluate_profile
from app.modules.whois.models import WhoisProfile
from app.modules.whois.scanner import python_whois
from app.modules.whois.service import run_whois_check

DAYS = datetime.timedelta(days=1)
UTC = datetime.timezone.utc


@dataclass
class FakeWhois:
    """Stand-in for the object returned by python-whois."""

    registrar: str | None = None
    creation_date: Any = None
    updated_date: Any = None
    expiration_date: Any = None
    organization: str | None = None
    country: str | None = None
    dnssec: str | None = None
    registrar_url: str | None = None
    name_servers: Any = None


def _days_from_now(n: int) -> datetime.datetime:
    return datetime.datetime.now(UTC) + datetime.timedelta(days=n)


def _titles(result) -> list[str]:
    return [f.title for f in result.findings]


# ---------------------------------------------------------------- unit rules

def test_recently_registered_domain_flagged():
    profile = WhoisProfile(
        domain="new-site.com",
        registrar="Fast Hosting",
        domain_age_days=5,
        expires_in_days=3650,
        name_servers=["ns1.example.com"],
    )

    result = evaluate_profile(profile)

    assert "Recently Registered Domain" in _titles(result)
    assert result.score == 70


def test_expired_domain_flagged():
    profile = WhoisProfile(
        domain="old-site.com",
        registrar="Registry B",
        domain_age_days=3000,
        expires_in_days=-10,
        name_servers=["ns1.example.com"],
    )

    result = evaluate_profile(profile)

    assert "Domain Expired" in _titles(result)
    assert result.score == 60


def test_expiring_domain_flagged():
    profile = WhoisProfile(
        domain="renew-me.com",
        registrar="Renewal Co",
        domain_age_days=300,
        expires_in_days=20,
        name_servers=["ns1.example.com"],
    )

    result = evaluate_profile(profile)

    assert "Domain Expiring Soon" in _titles(result)
    assert result.score == 80


def test_missing_registrar_flagged():
    profile = WhoisProfile(
        domain="mystery.com",
        domain_age_days=400,
        expires_in_days=300,
        name_servers=["ns1.example.com"],
    )

    result = evaluate_profile(profile)

    assert "Missing Registrar" in _titles(result)
    assert result.score == 85


def test_missing_nameservers_flagged():
    profile = WhoisProfile(
        domain="nodns.com",
        registrar="Acme Registrar",
        domain_age_days=400,
        expires_in_days=300,
    )

    result = evaluate_profile(profile)

    assert "No Name Servers Detected" in _titles(result)
    assert result.score == 80


def test_dnssec_disabled_flagged_low():
    profile = WhoisProfile(
        domain="unsigned.com",
        registrar="Acme Registrar",
        domain_age_days=400,
        expires_in_days=300,
        dnssec="unsigned",
        name_servers=["ns1.example.com"],
    )

    result = evaluate_profile(profile)

    assert "DNSSEC Disabled" in _titles(result)
    assert [f.severity for f in result.findings] == ["low"]


def test_healthy_profile_scores_100_without_findings():
    profile = WhoisProfile(
        domain="healthy.com",
        registrar="Example Registrar",
        domain_age_days=3000,
        expires_in_days=900,
        dnssec="signed",
        name_servers=["ns1.healthy.com"],
    )

    result = evaluate_profile(profile)

    assert result.score == 100
    assert result.findings == []
    assert result.confidence == 80


def test_multiple_rules_stack_penalties():
    profile = WhoisProfile(
        domain="risk.com",
        domain_age_days=5,
        expires_in_days=10,
        registrar="Acme Registrar",
        name_servers=["ns1.example.com"],
    )

    result = evaluate_profile(profile)

    assert result.score == 50  # 100 - 30 (recent) - 20 (expiring)
    assert "Recently Registered Domain" in _titles(result)
    assert "Domain Expiring Soon" in _titles(result)


# ------------------------------------------------------------ service level

def test_whois_unavailable_is_informational_not_a_security_finding(monkeypatch):
    def raise_error(_domain: str):
        raise RuntimeError("registry down")

    monkeypatch.setattr(python_whois, "whois", raise_error)

    result = run_whois_check("ghost.org")

    assert result.status == "error"
    assert result.score == 100
    assert result.confidence == 50
    assert _titles(result) == ["WHOIS Lookup Unavailable"]
    assert [f.severity for f in result.findings] == ["info"]
    assert result.details["domain"] == "ghost.org"
    assert "error" in result.details


def test_whois_returns_none_for_unsupported_tld(monkeypatch):
    monkeypatch.setattr(python_whois, "whois", lambda _domain: None)

    result = run_whois_check("example.invalidtld")

    assert result.status == "error"
    assert result.score == 100
    assert [f.severity for f in result.findings] == ["info"]
    assert _titles(result) == ["WHOIS Lookup Unavailable"]


def test_whois_unavailable_does_not_increase_risk_or_create_malicious_finding(monkeypatch):
    from app.risk_engine.engine import calculate_risk_score
    from app.schemas.module_result import ModuleResult

    def raise_error(_domain: str):
        raise RuntimeError("registry down")

    monkeypatch.setattr(python_whois, "whois", raise_error)

    unavailable = run_whois_check("ghost.org")
    response = calculate_risk_score(
        {
            "url_analysis": ModuleResult(module="url_analysis", score=100, confidence=100),
            "whois": unavailable,
        }
    )

    assert unavailable.score == 100
    assert [f.severity for f in unavailable.findings] == ["info"]
    assert not any(
        f.severity in {"critical", "high", "medium"} for f in response.findings
    )
    assert response.verdict == "Trusted"


def test_newly_registered_domain_end_to_end(monkeypatch):
    monkeypatch.setattr(
        python_whois,
        "whois",
        lambda _domain: FakeWhois(
            registrar="Fast Hosting",
            creation_date=_days_from_now(-5),
            expiration_date=_days_from_now(300),
            name_servers=["ns1.example.com"],
        ),
    )

    result = run_whois_check("new-brand.com")

    assert result.status == "warning"
    assert "Recently Registered Domain" in _titles(result)
    assert result.details["domain_age_days"] <= 5
    assert result.details["name_server_count"] == 1


def test_expiring_domain_end_to_end(monkeypatch):
    monkeypatch.setattr(
        python_whois,
        "whois",
        lambda _domain: FakeWhois(
            registrar="Renewal Co",
            creation_date=_days_from_now(-1000),
            expiration_date=_days_from_now(15),
            name_servers=["ns1.example.com"],
        ),
    )

    result = run_whois_check("almost-expired.com")

    assert "Domain Expiring Soon" in _titles(result)
    assert result.details["expires_in_days"] <= 15


def test_expired_domain_end_to_end(monkeypatch):
    monkeypatch.setattr(
        python_whois,
        "whois",
        lambda _domain: FakeWhois(
            registrar="Registry B",
            creation_date=_days_from_now(-2000),
            expiration_date=_days_from_now(-10),
            name_servers=["ns1.example.com"],
        ),
    )

    result = run_whois_check("dead-domain.com")

    assert "Domain Expired" in _titles(result)
    assert result.details["expires_in_days"] < 0


def test_malformed_whois_handled_gracefully(monkeypatch):
    monkeypatch.setattr(
        python_whois,
        "whois",
        lambda _domain: FakeWhois(
            registrar="",
            creation_date="not-a-date",
            updated_date=["also-bad", "x"],
            expiration_date=None,
            organization=None,
            country=None,
            dnssec=None,
            name_servers={"nserver": ["ns1.example.com"]},
        ),
    )

    result = run_whois_check("messy.com")

    assert result.status == "warning"
    assert result.details["creation_date"] is None
    assert result.details["domain_age_days"] is None
    assert result.details["name_servers"] == ["ns1.example.com"]
    assert "Missing Registrar" in _titles(result)


def test_details_include_frontend_fields(monkeypatch):
    monkeypatch.setattr(
        python_whois,
        "whois",
        lambda _domain: FakeWhois(
            registrar="Example Registrar",
            creation_date="2020-01-01",
            expiration_date="2030-01-01",
            organization="Big Org",
            country="US",
            dnssec="signed",
            registrar_url="https://registrar.example",
            name_servers=["ns1.example.com", "ns2.example.com"],
        ),
    )

    result = run_whois_check("example.com")

    details = result.details
    assert details["domain"] == "example.com"
    assert details["registrar"] == "Example Registrar"
    assert details["organization"] == "Big Org"
    assert details["country"] == "US"
    assert details["name_server_count"] == 2
    assert details["name_servers"] == ["ns1.example.com", "ns2.example.com"]
    assert details["creation_date"] == "2020-01-01T00:00:00+00:00"
    assert details["domain_age_days"] is not None
    assert details["expires_in_days"] is not None