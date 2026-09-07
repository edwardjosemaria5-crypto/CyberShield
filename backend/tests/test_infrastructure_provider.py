"""Tests for the IPWHOIS (ipwho.is) infrastructure provider adapter.

Every external call is mocked with httpx.MockTransport — no live API, no
real keys (the provider is keyless anyway). Coverage follows the Phase 3B
milestone contract:

- success mapping: ASN/org/ISP/country/region normalization, IPv4 + IPv6
  literal URLs, ASN integer/string canonicalization, junk types ignored
- trust boundary: IP-echo mismatch, missing echo, ``success=false``,
  non-object/malformed payloads — all ``bad_response``/``no_analysis``
- failure isolation: timeout, connect error, 401, 403, 429, 5xx, unknown
  HTTP status — all degrade to ``UnavailableData``, never crash
- bounded output: oversized provider strings truncated to ``MAX_FIELD_LEN``
- defense-in-depth: non-literal inputs rejected before any HTTP transport
- service wiring: ``build_adapter()`` selects the adapter only on slug match
- scanner integration: full adapter path through
  ``scan_infrastructure_module`` stays informational (score 100, no findings)
"""

import socket

import httpx
import pytest

from app.modules.infrastructure.adapter import (
    InfrastructureAdapter,
    InfrastructureData,
    UnavailableData,
)
from app.modules.infrastructure.ipwhois import IPWHOIS_ENDPOINT, IpwhoisAdapter
from app.modules.infrastructure.rules import MAX_FIELD_LEN, PROVIDER_IPWHOIS
from app.modules.infrastructure.scanner import scan_infrastructure_module
from app.modules.infrastructure.service import build_adapter

EXAMPLE_IP = "93.184.216.34"
EXAMPLE_IPV6 = "2606:2800:220:1:248:1893:25c8:1946"


def full_payload(ip: str = EXAMPLE_IP) -> dict:
    return {
        "ip": ip,
        "success": True,
        "type": "IPv4",
        "country": "United States",
        "country_code": "US",
        "region": "California",
        "city": "Malibu",
        "connection": {
            "asn": 15133,
            "org": "EdgeCast Networks, Inc.",
            "isp": "MCI Communications Services",
            "domain": "edgecast.com",
        },
    }


def json_response(payload: dict, status: int = 200) -> httpx.Response:
    return httpx.Response(status, json=payload)


def make_adapter(handler) -> IpwhoisAdapter:
    return IpwhoisAdapter(timeout_seconds=1.0, transport=httpx.MockTransport(handler))


# ---------------------------------------------------------------- success path

def test_lookup_success_maps_all_fields():
    def handler(request):
        assert request.url == f"{IPWHOIS_ENDPOINT}/{EXAMPLE_IP}"
        return json_response(full_payload())

    result = make_adapter(handler).lookup(EXAMPLE_IP)

    assert isinstance(result, InfrastructureData)
    assert result.ip == EXAMPLE_IP
    assert result.asn == "AS15133"
    assert result.asn_organization == "EdgeCast Networks, Inc."
    assert result.isp == "MCI Communications Services"
    assert result.country == "United States"
    assert result.country_code == "US"
    assert result.region == "California"
    assert result.source == "ipwhois"
    assert result.network is None
    assert result.reverse_dns is None


def test_ipv6_literal_queried_in_path():
    def handler(request):
        assert request.url == f"{IPWHOIS_ENDPOINT}/{EXAMPLE_IPV6}"
        return json_response(full_payload(ip=EXAMPLE_IPV6))

    result = make_adapter(handler).lookup(EXAMPLE_IPV6)

    assert isinstance(result, InfrastructureData)
    assert result.ip == EXAMPLE_IPV6


# ----------------------------------------------------------------- ASN mapping

@pytest.mark.parametrize(
    "raw, expected",
    [
        (15133, "AS15133"),
        ("15133", "AS15133"),
        ("AS15133", "AS15133"),
        ("as15133", "AS15133"),
    ],
)
def test_asn_canonicalized(raw, expected):
    payload = full_payload()
    payload["connection"]["asn"] = raw

    result = make_adapter(lambda r: json_response(payload)).lookup(EXAMPLE_IP)

    assert isinstance(result, InfrastructureData)
    assert result.asn == expected


@pytest.mark.parametrize("raw", [None, {}, ["AS1"], "not-an-asn", True])
def test_unrecognized_asn_stays_none(raw):
    payload = full_payload()
    payload["connection"]["asn"] = raw

    result = make_adapter(lambda r: json_response(payload)).lookup(EXAMPLE_IP)

    assert isinstance(result, InfrastructureData)
    assert result.asn is None


def test_wrong_types_ignored_not_coerced():
    payload = full_payload()
    payload["connection"]["isp"] = ["MCI"]
    payload["connection"]["org"] = {"name": "EdgeCast"}
    payload["country"] = 123

    result = make_adapter(lambda r: json_response(payload)).lookup(EXAMPLE_IP)

    assert isinstance(result, InfrastructureData)
    assert result.isp is None
    assert result.asn_organization is None
    assert result.country is None
    assert result.country_code == "US"


def test_missing_connection_is_sparse_but_available():
    payload = {"ip": EXAMPLE_IP, "success": True, "country": "United States"}

    result = make_adapter(lambda r: json_response(payload)).lookup(EXAMPLE_IP)

    assert isinstance(result, InfrastructureData)
    assert result.country == "United States"
    assert result.asn is None
    assert result.asn_organization is None
    assert result.isp is None
    assert result.region is None


# -------------------------------------------------------------- trust boundary

def test_ip_echo_mismatch_is_bad_response():
    payload = full_payload(ip="203.0.113.9")

    result = make_adapter(lambda r: json_response(payload)).lookup(EXAMPLE_IP)

    assert isinstance(result, UnavailableData)
    assert result.reason == "bad_response"


def test_missing_ip_echo_is_bad_response():
    payload = full_payload()
    del payload["ip"]

    result = make_adapter(lambda r: json_response(payload)).lookup(EXAMPLE_IP)

    assert isinstance(result, UnavailableData)
    assert result.reason == "bad_response"


def test_success_false_maps_to_no_analysis():
    payload = {"success": False, "message": "invalid IP address"}

    result = make_adapter(lambda r: json_response(payload)).lookup(EXAMPLE_IP)

    assert isinstance(result, UnavailableData)
    assert result.reason == "no_analysis"
    assert result.detail == "invalid IP address"


def test_success_false_message_is_bounded():
    payload = {"success": False, "message": "x" * 500}

    result = make_adapter(lambda r: json_response(payload)).lookup(EXAMPLE_IP)

    assert isinstance(result, UnavailableData)
    assert result.reason == "no_analysis"
    assert len(result.detail) <= MAX_FIELD_LEN


def test_non_object_payload_is_bad_response():
    result = make_adapter(lambda r: json_response([1, 2, 3])).lookup(EXAMPLE_IP)

    assert isinstance(result, UnavailableData)
    assert result.reason == "bad_response"


def test_malformed_json_is_bad_response():
    def handler(request):
        return httpx.Response(200, content=b"<html>not json</html>")

    result = make_adapter(handler).lookup(EXAMPLE_IP)

    assert isinstance(result, UnavailableData)
    assert result.reason == "bad_response"


def test_oversized_string_fields_truncated_to_80():
    payload = full_payload()
    payload["connection"]["isp"] = "X" * 500
    payload["country"] = "Y" * 500

    result = make_adapter(lambda r: json_response(payload)).lookup(EXAMPLE_IP)

    assert isinstance(result, InfrastructureData)
    assert len(result.isp) == MAX_FIELD_LEN
    assert len(result.country) == MAX_FIELD_LEN


# ------------------------------------------------------------ failure isolation

def test_timeout_maps_to_timeout():
    def handler(request):
        raise httpx.ConnectTimeout("cancelled")

    result = make_adapter(handler).lookup(EXAMPLE_IP)

    assert isinstance(result, UnavailableData)
    assert result.reason == "timeout"
    assert result.provider == "ipwhois"


def test_connect_error_maps_to_network():
    def handler(request):
        raise httpx.ConnectError("boom")

    result = make_adapter(handler).lookup(EXAMPLE_IP)

    assert isinstance(result, UnavailableData)
    assert result.reason == "network"


@pytest.mark.parametrize(
    "status, expected_reason",
    [
        (400, "unknown"),
        (401, "unauthorized"),
        (403, "unauthorized"),
        (404, "unknown"),
        (418, "unknown"),
        (429, "rate_limited"),
        (500, "server_error"),
        (503, "server_error"),
    ],
)
def test_http_status_mapping(status, expected_reason):
    def handler(request):
        return httpx.Response(status, json={"kept": "but_unused"})

    result = make_adapter(handler).lookup(EXAMPLE_IP)

    assert isinstance(result, UnavailableData)
    assert result.reason == expected_reason


# ----------------------------------------------------------------- redirects

def test_redirect_302_is_not_followed():
    """A 302 with a ``Location`` header must not create a second request.

    ``follow_redirects=False`` is explicit; the redirect destination must
    never be contacted. The 3xx reply surfaces as an unhandled HTTP status
    → ``unknown`` unavailable (never a redirect-follow, never a verdict).
    """
    seen: list[str] = []

    def handler(request):
        seen.append(str(request.url))
        return httpx.Response(
            302,
            headers={"Location": "https://example.com/"},
            json={"success": True, "ip": EXAMPLE_IP},
        )

    result = make_adapter(handler).lookup(EXAMPLE_IP)

    assert isinstance(result, UnavailableData)
    assert result.reason == "unknown"
    assert result.detail == "Provider returned HTTP 302."
    assert seen == [f"{IPWHOIS_ENDPOINT}/{EXAMPLE_IP}"]


@pytest.mark.parametrize("status", [301, 302, 303, 307, 308])
def test_redirect_statuses_never_trigger_second_request(status):
    """None of the RFC redirect statuses may be followed.

    Exactly ONE request is issued — to the fixed provider endpoint only —
    and the ``Location`` target receives zero traffic.
    """
    seen: list[str] = []

    def handler(request):
        seen.append(str(request.url))
        return httpx.Response(
            status,
            headers={"Location": "http://127.0.0.1/internal"},
            json={"success": True, "ip": EXAMPLE_IP},
        )

    result = make_adapter(handler).lookup(EXAMPLE_IP)

    assert isinstance(result, UnavailableData)
    assert result.reason == "unknown"
    assert seen == [f"{IPWHOIS_ENDPOINT}/{EXAMPLE_IP}"]


# -------------------------------------------------------------- input boundary

def test_non_literal_argument_rejected_before_http():
    def handler(request):
        raise AssertionError("transport must not be contacted")

    adapter = make_adapter(handler)
    for bad in [
        "example.com",
        "https://example.com",
        "https://user:pass@example.com/path",
        "user:pass@example.com",
        "",
        "93.184.216.34/../../admin",
    ]:
        result = adapter.lookup(bad)
        assert isinstance(result, UnavailableData), f"expected unavailable for {bad!r}"
        assert result.reason == "invalid_target", bad


def test_keyless_adapter_is_configurable():
    adapter = IpwhoisAdapter()
    assert adapter.is_configurable is True


def test_adapter_extends_base_contract():
    assert isinstance(IpwhoisAdapter(), InfrastructureAdapter)


# ---------------------------------------------------------------- service wiring

def test_build_adapter_selects_ipwhois(monkeypatch):
    monkeypatch.setattr("app.modules.infrastructure.service.INFRASTRUCTURE_PROVIDER", PROVIDER_IPWHOIS)

    adapter = build_adapter()

    assert isinstance(adapter, IpwhoisAdapter)


@pytest.mark.parametrize("provider", ["", "unknown", "virustotal"])
def test_build_adapter_unknown_or_empty_slug_returns_none(monkeypatch, provider):
    monkeypatch.setattr("app.modules.infrastructure.service.INFRASTRUCTURE_PROVIDER", provider)

    assert build_adapter() is None


# ---------------------------------------------------------- scanner integration

def _monkey_dns(monkeypatch, ips):
    def fake_getaddrinfo(host, *_args, **_kwargs):
        if ips is None:
            raise socket.gaierror("no such host")
        return [(socket.AF_INET, socket.SOCK_STREAM, 0, "", (ip, 0)) for ip in ips]

    monkeypatch.setattr("app.utils.networking.socket.getaddrinfo", fake_getaddrinfo)


def test_scanner_enriches_with_ipwhois_adapter(monkeypatch):
    _monkey_dns(monkeypatch, [EXAMPLE_IP])
    adapter = IpwhoisAdapter(
        timeout_seconds=1.0,
        transport=httpx.MockTransport(lambda r: json_response(full_payload())),
    )

    result = scan_infrastructure_module("example.com", adapter=adapter)

    assert result.status == "ok"
    assert result.score == 100
    assert result.confidence == 100
    assert result.findings == []
    profile = result.details["infrastructure"]
    assert profile["status"] == "available"
    assert profile["source"] == "ipwhois"
    assert profile["ip_address"] == EXAMPLE_IP
    assert profile["asn"] == "AS15133"
    assert profile["isp"] == "MCI Communications Services"


def test_scanner_provider_failure_stays_informational(monkeypatch):
    _monkey_dns(monkeypatch, [EXAMPLE_IP])
    adapter = IpwhoisAdapter(
        timeout_seconds=1.0,
        transport=httpx.MockTransport(lambda r: httpx.Response(500, json={})),
    )

    result = scan_infrastructure_module("example.com", adapter=adapter)

    assert result.status == "ok"
    assert result.score == 100
    assert result.findings == []
    profile = result.details["infrastructure"]
    assert profile["status"] == "unavailable"
    assert profile["reason"] == "server_error"
    assert profile["ip_address"] is None