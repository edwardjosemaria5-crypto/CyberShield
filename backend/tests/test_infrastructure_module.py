"""Tests for the v1.1 infrastructure location module (Phase 2 hardened).

Covers:
- enrichment into the normalized ``InfrastructureProfile`` under
  ``details["infrastructure"]``
- every failure path (disabled, missing key, unresolvable target, provider
  errors, unexpected result types) degrading to ``unavailable`` with score
  100 and no findings — never a verdict
- IP resolution alignment: shared ``parse_host()`` / ``resolve_public_host()``
  from ``app.utils.networking`` — no independent resolution logic
- private/reserved targets: no provider contact for 127.0.0.1, 10.0.0.1,
  192.168.1.1, localhost
- non-canonical numeric hosts: 2130706433, 0x7f000001, 0177.0.0.1, 127.1,
  010.000.000.001 — safe rejection with no provider contact
- mixed DNS answers: shared all-or-nothing policy honored (public+private
  → refused)
- detail bounding: schema-level ``max_length`` rejects oversized details at
  the model boundary, and the scanner isolates a hostile adapter that
  constructs one inside ``lookup()`` to ``bad_response`` (never a leak) —
  plus call-site ``_bound_detail`` pass-through for short/empty details
- adapter configuration safety: ``is_configurable`` defaults to ``False``
- scoring isolation: the module is absent from ``MODULE_WEIGHTS`` and can
  never move the Trust Score, verdict, confidence, summary or any other
  module's result
"""

import socket

import pytest
from pydantic import ValidationError

from app.modules.infrastructure.adapter import (
    InfrastructureAdapter,
    InfrastructureData,
    UnavailableData,
)
from app.modules.infrastructure.scanner import (
    scan_infrastructure_module,
)
from app.modules.infrastructure.service import run_infrastructure_check
from app.risk_engine.engine import calculate_risk_score
from app.schemas.finding import Finding
from app.schemas.module_result import ModuleResult
from app.utils.networking import parse_host, resolve_public_host

EXAMPLE_IP = "93.184.216.34"
EXAMPLE_IPV6 = "2606:2800:220:1:248:1893:25c8:1946"

FULL_DATA = InfrastructureData(
    ip=EXAMPLE_IP,
    asn="AS15133",
    asn_organization="EdgeCast Networks, Inc.",
    isp="MCI Communications Services",
    hosting_provider="EdgeCast Networks, Inc.",
    network="93.184.216.0/24",
    reverse_dns="edgecastcdn.net",
    country="United States",
    country_code="US",
    region="California",
    source="fake",
)


class FakeAdapter(InfrastructureAdapter):
    """Deterministic adapter stub; records every lookup it receives."""

    provider = "fake"

    def __init__(self, results=None, configurable=True, fail=False):
        super().__init__()
        self.results = dict(results or {})
        self.calls: list[str] = []
        self.configurable = configurable
        self.fail = fail

    @property
    def is_configurable(self):
        return self.configurable

    def lookup(self, ip_address):
        self.calls.append(ip_address)
        if self.fail:
            raise RuntimeError("provider exploded")
        if ip_address in self.results:
            return self.results[ip_address]
        return UnavailableData(provider=self.provider, reason="no_analysis", detail="no row for ip")


def _monkey_dns(monkeypatch, ips):
    """Pin ``socket.getaddrinfo`` in the networking module to a fixed list.

    ``None`` → unresolvable (``gaierror``).
    ``ips`` is a list of IP address strings the resolver returns.
    """
    def fake_getaddrinfo(host, *_args, **_kwargs):
        if ips is None:
            raise socket.gaierror("no such host")
        return [(socket.AF_INET, socket.SOCK_STREAM, 0, "", (ip, 0)) for ip in ips]

    monkeypatch.setattr("app.utils.networking.socket.getaddrinfo", fake_getaddrinfo)


# ============================================================ 1. shared parser

def test_shared_parse_host_used(monkeypatch):
    """Infrastructure normalizes targets via the shared parse_host()."""
    _monkey_dns(monkeypatch, [EXAMPLE_IP])
    adapter = FakeAdapter({EXAMPLE_IP: FULL_DATA})

    for target, expected in [
        ("example.com", "example.com"),
        ("https://example.com", "example.com"),
        ("http://example.com/path?q=1", "example.com"),
        ("EXAMPLE.COM", "example.com"),
        ("https://user:pass@example.com", "example.com"),
        ("http://admin@10.0.0.1/secret", "10.0.0.1"),
    ]:
        result = scan_infrastructure_module(target, adapter=adapter)
        assert result.details["infrastructure"]["domain"] == expected
        assert result.details["domain"] == expected


def test_ipv6_bracketed_form_parsed():
    """Bracketed IPv6 with port is correctly parsed by shared parse_host."""
    assert parse_host("[::1]:8443") == "::1"


def test_userinfo_stripped_before_resolution():
    """Userinfo never leaks into the hostname passed to the adapter."""
    assert parse_host("https://admin:secret@evil.example.com/") == "evil.example.com"


# ============================================================ 2. reserved/private

def test_private_ip_targets_refused(monkeypatch):
    """Private/reserved IPs never reach the adapter."""
    adapter = FakeAdapter({})

    for target in ["127.0.0.1", "10.0.0.1", "192.168.1.1", "localhost"]:
        result = scan_infrastructure_module(target, adapter=adapter)
        assert result.details["infrastructure"]["reason"] in (
            "invalid_target",
            "missing_api_key",
        )
        assert adapter.calls == []


def test_loopback_ipv6_refused():
    """Loopback IPv6 is rejected by the shared networking layer."""
    result = scan_infrastructure_module("[::1]", adapter=FakeAdapter({}))
    assert result.details["infrastructure"]["status"] == "unavailable"


def test_localhost_subdomain_refused():
    """'foo.localhost' is rejected by resolve_public_host()."""
    result = scan_infrastructure_module("foo.localhost", adapter=FakeAdapter({}))
    assert result.details["infrastructure"]["status"] == "unavailable"


def test_dot_local_refused():
    """'foo.local' is rejected by resolve_public_host()."""
    result = scan_infrastructure_module("foo.local", adapter=FakeAdapter({}))
    assert result.details["infrastructure"]["status"] == "unavailable"


# ============================================================ 3. non-canonical numeric

def test_numeric_host_forms_rejected():
    """Non-canonical numeric host forms are refused by shared networking."""
    adapter = FakeAdapter({})
    non_canonical = [
        "2130706433",
        "0x7f000001",
        "0177.0.0.1",
        "127.1",
        "010.000.000.001",
    ]
    for target in non_canonical:
        result = scan_infrastructure_module(target, adapter=adapter)
        assert result.details["infrastructure"]["status"] == "unavailable"
        assert result.details["infrastructure"]["reason"] == "invalid_target"
        assert adapter.calls == [], f"adapter was called for {target}"


def test_numeric_rejection_uses_shared_policy():
    """The reason string matches what resolve_public_host() returns."""
    result = scan_infrastructure_module("2130706433", adapter=FakeAdapter({}))
    detail = result.details.get("detail", "")
    assert "non-canonical" in detail.lower() or "numeric" in detail.lower()


# ============================================================ 4. mixed DNS

def test_mixed_public_private_dns_rejected(monkeypatch):
    """When DNS returns both public and private addresses, the shared
    resolve_public_host() all-or-nothing policy rejects the target.

    The old per-address filtering silently kept public IPs from mixed
    answers.  The hardened infrastructure module now follows the shared
    policy and rejects the entire target.
    """
    _monkey_dns(monkeypatch, ["93.184.216.34", "10.0.0.1"])
    adapter = FakeAdapter({"93.184.216.34": FULL_DATA})

    result = scan_infrastructure_module("example.com", adapter=adapter)

    assert result.details["infrastructure"]["status"] == "unavailable"
    assert result.details["infrastructure"]["reason"] == "invalid_target"
    assert adapter.calls == [], "adapter must NOT be contacted with mixed DNS"


# ============================================================ 5. valid public multi-IP

def test_valid_public_multi_ip_resolution(monkeypatch):
    """Multiple public IPs are resolved; only validated IP literals reach
    the adapter and are returned in ``resolved_ips``."""
    ip_a = "1.1.1.1"
    ip_b = "8.8.8.8"
    _monkey_dns(monkeypatch, [ip_a, ip_b])
    data_a = InfrastructureData(ip=ip_a, asn="AS13335", source="fake")
    data_b = InfrastructureData(ip=ip_b, asn="AS15169", source="fake")
    adapter = FakeAdapter({ip_a: data_a, ip_b: data_b})

    result = scan_infrastructure_module("example.com", adapter=adapter, max_ips=10)

    profile = result.details["infrastructure"]
    assert profile["status"] == "available"
    assert ip_a in result.details["resolved_ips"]
    assert ip_b in result.details["resolved_ips"]
    # First public IP is queried first (deterministic ordering)
    assert adapter.calls[0] == ip_a
    # Hostname never passed to adapter — only IP literals
    assert all(is_ip_literal(c) for c in adapter.calls)


def test_hostname_never_passed_to_adapter(monkeypatch):
    """Security assertion: adapter.lookup() receives only IP literals."""
    _monkey_dns(monkeypatch, [EXAMPLE_IP])
    adapter = FakeAdapter({EXAMPLE_IP: FULL_DATA})

    scan_infrastructure_module("example.com", adapter=adapter)

    for call in adapter.calls:
        assert is_ip_literal(call), f"non-IP literal passed to adapter: {call!r}"


def test_adversarial_raw_url_never_reaches_adapter(monkeypatch):
    """Adapter boundary contract: only validated public IP literals cross.

    A hostile raw URL carrying scheme, userinfo, path and query must
    never reach ``adapter.lookup()`` — not the hostname, the userinfo
    ``user:pass@`` form, nor the raw target itself. The caller receives
    exactly the single validated public IP literal the domain resolved to.
    """
    _monkey_dns(monkeypatch, [EXAMPLE_IP])
    adapter = FakeAdapter({EXAMPLE_IP: FULL_DATA})

    raw_target = "https://user:pass@example.com/suspicious/path?x=1"
    result = scan_infrastructure_module(raw_target, adapter=adapter)

    assert result.details["infrastructure"]["status"] == "available"
    assert result.details["domain"] == "example.com"
    # Positive contract: the adapter got exactly the resolved public IP.
    assert adapter.calls == [EXAMPLE_IP]
    assert all(is_ip_literal(c) for c in adapter.calls)
    # Negative contract: no forbidden form (raw/URL/host/userinfo/credential)
    # ever reached lookup().
    for forbidden in [
        raw_target,
        "https://user:pass@example.com/suspicious/path?x=1",
        "example.com",
        "https://example.com",
        "user:pass@example.com",
        "user:pass",
        "http://admin@10.0.0.1/secret",
    ]:
        assert forbidden not in adapter.calls, f"forbidden value reached adapter: {forbidden!r}"


def test_resolved_ips_from_shared_target(monkeypatch):
    """resolved_ips come from ResolvedTarget.addresses (shared layer)."""
    _monkey_dns(monkeypatch, [EXAMPLE_IP])
    adapter = FakeAdapter({EXAMPLE_IP: FULL_DATA})

    result = scan_infrastructure_module("example.com", adapter=adapter)

    assert result.details["resolved_ips"] == [EXAMPLE_IP]


# ============================================================ 6. detail bounding

def test_short_detail_intact(monkeypatch):
    """Short unavailable detail is preserved unchanged."""
    _monkey_dns(monkeypatch, [EXAMPLE_IP])
    result = scan_infrastructure_module(
        "example.com",
        adapter=FakeAdapter(
            {EXAMPLE_IP: UnavailableData(reason="timeout", detail="slow")}
        ),
        max_ips=1,
    )
    assert result.details["detail"] == "slow"


def test_oversized_detail_rejected_by_schema():
    """Schema defense-in-depth: the model refuses an >80-char detail.

    A future adapter that skips the scanner's call-site ``_bound_detail``
    cannot even represent an unbounded detail on the model.
    """
    with pytest.raises(ValidationError):
        UnavailableData(reason="timeout", detail="X" * 500)


def test_schema_rejects_internal_payload_leak():
    """Provider internals (e.g. an API key embedded in a detail) cannot be
    carried by the model: construction with an oversized internal message
    raises before anything is persisted or returned."""
    internal_msg = "API_KEY=secret123 & " + "Z" * 400
    with pytest.raises(ValidationError):
        UnavailableData(reason="bad_response", detail=internal_msg)


class OversizeDetailAdapter(InfrastructureAdapter):
    """Hostile adapter that constructs ``UnavailableData`` directly with an
    oversized detail (forgetting the call-site bound) — the schema rejects
    it, and the scanner must degrade to ``bad_response`` without crashing."""

    provider = "oversize"

    @property
    def is_configurable(self):
        return True

    def lookup(self, ip_address):
        return UnavailableData(reason="timeout", detail="X" * 500)


def test_adapter_oversized_detail_degrades_to_bad_response(monkeypatch):
    """A hostile adapter constructing an oversized UnavailableData inside
    ``lookup()`` raises at the model boundary; ``_lookup`` isolates it and
    the scan continues as unavailable — never a crash, never a leak."""
    _monkey_dns(monkeypatch, [EXAMPLE_IP])
    result = scan_infrastructure_module("example.com", adapter=OversizeDetailAdapter())

    assert result.details["infrastructure"]["status"] == "unavailable"
    assert result.details["infrastructure"]["reason"] == "bad_response"
    assert result.score == 100
    detail = result.details.get("detail", "")
    assert "X" * 500 not in detail
    assert len(detail) <= 80


def test_none_detail_stays_none(monkeypatch):
    """None detail is not coerced to a string."""
    _monkey_dns(monkeypatch, [EXAMPLE_IP])
    adapter = FakeAdapter(
        {EXAMPLE_IP: UnavailableData(reason="timeout", detail="")}
    )
    result = scan_infrastructure_module("example.com", adapter=adapter, max_ips=1)
    # Empty string detail → _bound_detail("") → None → no "detail" key
    assert "detail" not in result.details


# ============================================================ 7. adapter config safety

def test_base_adapter_not_configurable():
    """A bare InfrastructureAdapter subclass must NOT be configurable."""
    class BareAdapter(InfrastructureAdapter):
        provider = "bare"
        def lookup(self, ip_address):
            raise NotImplementedError

    assert BareAdapter().is_configurable is False


def test_fake_adapter_explicitly_configurable():
    """FakeAdapter overrides is_configurable to True — explicit opt-in."""
    assert FakeAdapter().is_configurable is True


def test_unconfigurable_adapter_yields_missing_api_key():
    """An adapter with is_configurable=False → missing_api_key."""
    class NoKeyAdapter(InfrastructureAdapter):
        provider = "nokey"
        def lookup(self, ip_address):
            raise NotImplementedError

    result = scan_infrastructure_module("example.com", adapter=NoKeyAdapter())
    assert result.details["infrastructure"]["status"] == "unavailable"
    assert result.details["infrastructure"]["reason"] == "missing_api_key"


# ============================================================ 8. failure isolation

def test_no_adapter_returns_unavailable():
    """adapter=None → unavailable, no crash."""
    result = scan_infrastructure_module("example.com", adapter=None)
    assert result.details["infrastructure"]["status"] == "unavailable"
    assert result.score == 100


def test_adapter_exception_degrades_safely(monkeypatch):
    """Adapter raising RuntimeError → unavailable, scan continues."""
    _monkey_dns(monkeypatch, [EXAMPLE_IP])
    result = scan_infrastructure_module(
        "example.com", adapter=FakeAdapter({}, fail=True)
    )
    assert result.details["infrastructure"]["status"] == "unavailable"
    assert result.details["infrastructure"]["reason"] == "bad_response"
    assert result.score == 100


def test_malformed_return_type_degrades_safely(monkeypatch):
    """Adapter returning a dict instead of model → unavailable."""
    _monkey_dns(monkeypatch, [EXAMPLE_IP])
    adapter = FakeAdapter({})
    adapter.results[EXAMPLE_IP] = {"asn": "AS15133"}

    result = scan_infrastructure_module("example.com", adapter=adapter)

    assert result.details["infrastructure"]["reason"] == "bad_response"
    assert result.score == 100


def test_wrong_return_type_degrades_safely(monkeypatch):
    """Adapter returning an unexpected class → unavailable."""
    _monkey_dns(monkeypatch, [EXAMPLE_IP])
    adapter = FakeAdapter({})
    adapter.results[EXAMPLE_IP] = "not_a_model"

    result = scan_infrastructure_module("example.com", adapter=adapter)

    assert result.details["infrastructure"]["reason"] == "bad_response"
    assert result.score == 100


def test_dns_failure_never_contacts_provider(monkeypatch):
    """DNS resolution failure → invalid_target, zero provider calls."""
    _monkey_dns(monkeypatch, None)
    adapter = FakeAdapter({})

    result = scan_infrastructure_module("example.com", adapter=adapter)

    assert result.details["infrastructure"]["reason"] == "invalid_target"
    assert adapter.calls == []
    assert result.score == 100


# ============================================================ env wiring

def test_disabled_by_default_returns_unavailable(monkeypatch):
    monkeypatch.setattr("app.modules.infrastructure.service.INFRASTRUCTURE_ENABLED", False)

    result = run_infrastructure_check("example.com")

    assert result.module == "infrastructure"
    assert result.status == "ok"
    assert result.score == 100
    assert result.confidence == 100
    assert result.findings == []
    profile = result.details["infrastructure"]
    assert profile["status"] == "unavailable"
    assert profile["reason"] == "missing_api_key"


def test_enabled_but_no_provider_returns_unavailable(monkeypatch):
    monkeypatch.setattr("app.modules.infrastructure.service.INFRASTRUCTURE_ENABLED", True)

    result = run_infrastructure_check("example.com")

    assert result.details["infrastructure"]["reason"] == "missing_api_key"
    assert result.score == 100


# ============================================================ enrichment

def test_valid_enrichment_lands_in_details(monkeypatch):
    _monkey_dns(monkeypatch, [EXAMPLE_IP])
    adapter = FakeAdapter({EXAMPLE_IP: FULL_DATA})

    result = scan_infrastructure_module("example.com", adapter=adapter)

    assert result.module == "infrastructure"
    assert result.status == "ok"
    assert result.score == 100
    assert result.confidence == 100
    assert result.findings == []
    profile = result.details["infrastructure"]
    assert profile["status"] == "available"
    assert profile["ip_address"] == EXAMPLE_IP
    assert profile["asn"] == "AS15133"
    assert profile["asn_organization"] == "EdgeCast Networks, Inc."
    assert profile["isp"] == "MCI Communications Services"
    assert profile["hosting_provider"] == "EdgeCast Networks, Inc."
    assert profile["network"] == "93.184.216.0/24"
    assert profile["reverse_dns"] == "edgecastcdn.net"
    assert profile["country"] == "United States"
    assert profile["country_code"] == "US"
    assert profile["region"] == "California"
    assert profile["source"] == "fake"
    assert profile["timestamp"]
    assert result.details["resolved_ips"] == [EXAMPLE_IP]
    assert adapter.calls == [EXAMPLE_IP]


def test_missing_fields_stay_none_without_finding(monkeypatch):
    _monkey_dns(monkeypatch, [EXAMPLE_IP])
    partial = InfrastructureData(asn="AS15133", source="fake")

    result = scan_infrastructure_module(
        "example.com", adapter=FakeAdapter({EXAMPLE_IP: partial})
    )

    profile = result.details["infrastructure"]
    assert profile["status"] == "available"
    assert profile["asn"] == "AS15133"
    assert profile["country"] is None
    assert profile["region"] is None
    assert profile["isp"] is None
    assert result.findings == []
    assert result.score == 100


def test_ipv6_literal_is_normalized_and_queried(monkeypatch):
    _monkey_dns(monkeypatch, [EXAMPLE_IPV6])
    adapter = FakeAdapter(
        {
            EXAMPLE_IPV6: InfrastructureData(
                asn="AS15133", country_code="US", source="fake"
            )
        }
    )

    result = scan_infrastructure_module("example.com", adapter=adapter)

    profile = result.details["infrastructure"]
    assert profile["status"] == "available"
    assert profile["ip_address"] == EXAMPLE_IPV6
    assert profile["asn"] == "AS15133"
    assert adapter.calls == [EXAMPLE_IPV6]


def test_oversized_field_rejected_by_schema():
    """Schema defense-in-depth mirrors ``UnavailableData.detail``: an
    >80-char provider field cannot even be represented on the model."""
    with pytest.raises(ValidationError):
        InfrastructureData(asn_organization="X" * 500, source="fake")


class OversizeFieldAdapter(InfrastructureAdapter):
    """Hostile adapter that constructs ``InfrastructureData`` directly with an
    oversized field (skipping the adapter's truncation) — the schema rejects
    it, and the scanner must degrade to ``bad_response`` without crashing."""

    provider = "oversize"

    @property
    def is_configurable(self):
        return True

    def lookup(self, ip_address):
        return InfrastructureData(asn_organization="X" * 500, source="fake")


def test_adapter_oversized_field_degrades_to_bad_response(monkeypatch):
    """A hostile adapter constructing oversized InfrastructureData inside
    ``lookup()`` raises at the model boundary; ``_lookup`` isolates it and
    the scan continues as unavailable — never a crash, never a leak."""
    _monkey_dns(monkeypatch, [EXAMPLE_IP])
    result = scan_infrastructure_module("example.com", adapter=OversizeFieldAdapter())

    assert result.details["infrastructure"]["status"] == "unavailable"
    assert result.details["infrastructure"]["reason"] == "bad_response"
    assert result.score == 100
    assert result.findings == []


# ============================================================ resolution

def test_all_ip_lookups_failing_uses_first_reason(monkeypatch):
    _monkey_dns(monkeypatch, [EXAMPLE_IP, EXAMPLE_IPV6])
    adapter = FakeAdapter(
        {
            EXAMPLE_IP: UnavailableData(
                provider="fake", reason="timeout", detail="provider is slow"
            )
        }
    )

    result = scan_infrastructure_module("example.com", adapter=adapter)

    assert result.details["infrastructure"]["status"] == "unavailable"
    assert result.details["infrastructure"]["reason"] == "timeout"
    assert result.details["detail"] == "provider is slow"
    assert adapter.calls == [EXAMPLE_IP, EXAMPLE_IPV6]
    assert result.score == 100


def test_unresolvable_target_never_contacts_provider(monkeypatch):
    _monkey_dns(monkeypatch, None)
    adapter = FakeAdapter({})

    result = scan_infrastructure_module("example.com", adapter=adapter)

    assert result.details["infrastructure"]["reason"] == "invalid_target"
    assert result.details["infrastructure"]["status"] == "unavailable"
    assert adapter.calls == []
    assert result.score == 100


# ============================================================ scoring isolation

def test_scoring_isolation_against_hostile_module_result():
    base_results = {
        "url_analysis": ModuleResult(module="url_analysis", score=90, confidence=95),
        "dns": ModuleResult(module="dns", score=75, confidence=80),
        "headers": ModuleResult(
            module="headers",
            score=60,
            confidence=70,
            findings=[Finding(title="No HSTS", severity="medium")],
        ),
    }
    base = calculate_risk_score(base_results)
    extended = calculate_risk_score(
        {
            **base_results,
            "infrastructure": ModuleResult(
                module="infrastructure", score=0, confidence=0, status="critical"
            ),
        }
    )

    assert extended.trust_score == base.trust_score
    assert extended.confidence == base.confidence
    assert extended.verdict == base.verdict
    assert extended.summary == base.summary
    assert [f.title for f in extended.findings] == [f.title for f in base.findings]
    assert [m.module for m in extended.modules] == [
        "url_analysis",
        "dns",
        "headers",
        "infrastructure",
    ]


def test_scoring_isolation_with_real_module_output(monkeypatch):
    _monkey_dns(monkeypatch, [EXAMPLE_IP])
    dns = ModuleResult(module="dns", score=80, confidence=90)

    base = calculate_risk_score({"dns": dns})
    infra = scan_infrastructure_module(
        "example.com", adapter=FakeAdapter({EXAMPLE_IP: FULL_DATA})
    )
    extended = calculate_risk_score({"dns": dns, "infrastructure": infra})

    assert extended.trust_score == base.trust_score
    assert extended.confidence == base.confidence
    assert extended.verdict == base.verdict
    assert extended.summary == base.summary


def test_registry_includes_infrastructure_without_weight():
    from app.modules.registry import MODULE_REGISTRY
    from app.risk_engine.weights import MODULE_WEIGHTS

    names = [m.name for m in MODULE_REGISTRY]
    assert "infrastructure" in names
    assert names.count("infrastructure") == 1
    assert "infrastructure" not in MODULE_WEIGHTS


def test_infrastructure_scanner_is_domain_targeted():
    from app.modules.registry import InfrastructureScanner

    assert InfrastructureScanner().target_kind == "domain"


# ============================================================ helpers

def is_ip_literal(value: str) -> bool:
    """True when *value* is an IP address literal (v4 or v6), not a hostname."""
    import ipaddress
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False
