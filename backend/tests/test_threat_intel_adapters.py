"""Tests for the external threat-intel provider adapters (Google Safe Browsing).

The adapter is exercised against httpx.MockTransport so no real network calls
or API keys are ever used. The normalizing semantics under test:

- provider unavailable != verdict (never raises score)
- status codes map to canonical reason codes
- threat types map to canonical categories and verdicts
"""

import httpx
import pytest

from app.modules.threatintel.adapters import build_adapters
from app.modules.threatintel.adapters.google_safe_browsing import (
    ENDPOINT,
    GoogleSafeBrowsingAdapter,
)
from app.modules.threatintel.scanner import scan_threatintel_module

API_KEY = "test-key-not-a-real-key"


def json_response(payload: dict, status: int = 200) -> httpx.Response:
    return httpx.Response(status, json=payload, request=httpx.Request("POST", ENDPOINT))


def make_adapter(handler) -> GoogleSafeBrowsingAdapter:
    """Adapter wired to a MockTransport serving ``handler``."""
    transport = httpx.MockTransport(handler)
    return GoogleSafeBrowsingAdapter(
        api_key=API_KEY,
        timeout_seconds=1.0,
        transport=transport,
    )


# ------------------------------------------------------------- basic lookup

def test_clean_domain_is_not_malicious():
    adapter = make_adapter(lambda request: json_response({}))

    signals = adapter.lookup("https://example.com")

    assert signals.status == "available"
    assert signals.malicious is False
    assert signals.suspicious is False
    assert signals.detections == 0
    assert signals.categories == []


def test_malware_match_is_malicious():
    payload = {
        "matches": [
            {
                "threatType": "MALWARE",
                "platformType": "ANY_PLATFORM",
                "threat": {"url": "https://evil.example.com/"},
                "cacheDuration": "300s",
            }
        ]
    }
    adapter = make_adapter(lambda request: json_response(payload))

    signals = adapter.lookup("evil.example.com")

    assert signals.status == "available"
    assert signals.malicious is True
    assert signals.suspicious is False
    assert "malware" in signals.categories
    assert signals.detections == 1
    assert signals.evidence


def test_social_engineering_is_suspicious_not_malicious():
    payload = {
        "matches": [
            {
                "threatType": "SOCIAL_ENGINEERING",
                "threat": {"url": "https://phish.example.com/"},
            }
        ]
    }
    adapter = make_adapter(lambda request: json_response(payload))

    signals = adapter.lookup("phish.example.com")

    assert signals.status == "available"
    assert signals.malicious is False
    assert signals.suspicious is True
    assert "social-engineering" in signals.categories


def test_mixed_matches_fold_into_malicious():
    payload = {
        "matches": [
            {"threatType": "SOCIAL_ENGINEERING", "threat": {"url": "https://mix.example.com/"}},
            {"threatType": "UNWANTED_SOFTWARE", "threat": {"url": "https://mix.example.com/"}},
            {"threatType": "MALWARE", "threat": {"url": "https://mix.example.com/"}},
        ]
    }
    adapter = make_adapter(lambda request: json_response(payload))

    signals = adapter.lookup("mix.example.com")

    assert signals.malicious is True
    assert signals.suspicious is True
    assert set(signals.categories) == {"social-engineering", "unwanted-software", "malware"}


def test_unknown_threat_type_is_ignored():
    payload = {"matches": [{"threatType": "KITTEN_SCAN", "threat": {"url": "https://x.example.com/"}}]}
    adapter = make_adapter(lambda request: json_response(payload))

    signals = adapter.lookup("x.example.com")

    assert signals.status == "available"
    assert signals.malicious is False
    assert signals.suspicious is False
    assert signals.detections == 0
    assert signals.categories == []


def test_malformed_payload_is_bad_response():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            content=b"<html>not json</html>",
            request=request,
        )

    adapter = make_adapter(handler)

    signals = adapter.lookup("example.com")

    assert signals.status == "unavailable"
    assert signals.reason == "bad_response"
    assert signals.malicious is False
    assert signals.suspicious is False


# ------------------------------------------------------------- status codes

@pytest.mark.parametrize(
    ("status", "expected_reason"),
    [
        (429, "rate_limited"),
        (401, "unauthorized"),
        (403, "unauthorized"),
        (400, "invalid_target"),
        (500, "server_error"),
        (503, "server_error"),
    ],
)
def test_http_errors_map_to_reason_codes(status, expected_reason):
    adapter = make_adapter(lambda request: json_response({}, status=status))

    signals = adapter.lookup("example.com")

    assert signals.status == "unavailable"
    assert signals.reason == expected_reason
    assert signals.malicious is False


def test_timeout_is_unavailable():
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.TimeoutException("timeout", request=request)

    adapter = make_adapter(handler)

    signals = adapter.lookup("example.com")

    assert signals.status == "unavailable"
    assert signals.reason == "timeout"


def test_network_error_is_unavailable():
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("boom", request=request)

    adapter = make_adapter(handler)

    signals = adapter.lookup("example.com")

    assert signals.status == "unavailable"
    assert signals.reason == "network"


# ------------------------------------------------------------------ config

def test_missing_api_key_is_unavailable():
    adapter = GoogleSafeBrowsingAdapter(api_key=None)

    signals = adapter.lookup("example.com")

    assert signals.status == "unavailable"
    assert signals.reason == "missing_api_key"


def test_invalid_target_is_unavailable():
    adapter = make_adapter(lambda request: json_response({}))

    signals = adapter.lookup("this is not a url")

    assert signals.status == "unavailable"
    assert signals.reason == "invalid_target"


def test_build_adapters_skips_unconfigured_providers():
    assert build_adapters(google_safe_browsing_api_key=None) == []


def test_build_adapters_instantiates_configured_provider():
    adapters = build_adapters(google_safe_browsing_api_key=API_KEY)

    assert len(adapters) == 1
    assert isinstance(adapters[0], GoogleSafeBrowsingAdapter)


# ------------------------------------------------------- scanner integration

def test_scanner_without_adapters_is_unchanged():
    result = scan_threatintel_module("example.com")

    assert result.module == "threatintel"
    assert "external_threat_intel" in result.details
    assert result.details["external_threat_intel"] == []
    assert result.score == 100


def test_scanner_survives_unavailable_provider():
    adapter = make_adapter(lambda request: json_response({}, status=503))

    result = scan_threatintel_module("example.com", adapters=[adapter])

    assert result.score == 100
    # The failure surfaces as an info-level finding that must NOT imply a verdict.
    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding.severity == "info"
    assert finding.title == "External threat intelligence unavailable"
    assert "malicious" not in finding.explanation.lower()
    assert "could not" in finding.explanation.lower()


def test_scanner_applies_provider_malicious_signal():
    payload = {"matches": [{"threatType": "MALWARE", "threat": {"url": "https://evil.example.com/"}}]}
    adapter = make_adapter(lambda request: json_response(payload))

    result = scan_threatintel_module("evil.example.com", adapters=[adapter])

    # GSB adapter reports confidence=90 -> penalty = 35 * 0.9 = 31.5 -> 32.
    assert result.score == 68
    assert any(f.title == "External threat intelligence flag" for f in result.findings)
    signals = result.details["external_threat_intel"][0]
    assert signals["malicious"] is True
    assert signals["provider"] == "google-safe-browsing"


def test_scanner_applies_provider_suspicious_signal():
    payload = {
        "matches": [
            {"threatType": "SOCIAL_ENGINEERING", "threat": {"url": "https://phishy.example.com/"}}
        ]
    }
    adapter = make_adapter(lambda request: json_response(payload))

    result = scan_threatintel_module("phishy.example.com", adapters=[adapter])

    # GSB adapter reports confidence 90 -> penalty = 15 * 0.9 = 13.5 -> 14.
    assert result.score == 86
    assert any(f.title == "External threat intelligence suspicion" for f in result.findings)


def test_scanner_findings_keep_existing_heuristics_with_provider():
    payload = {"matches": [{"threatType": "MALWARE", "threat": {"url": "https://malware-test.org/"}}]}
    adapter = make_adapter(lambda request: json_response(payload))

    result = scan_threatintel_module("malware-test.org", adapters=[adapter])

    # Local feed flag (50) + provider malicious (35 @ confidence 90 -> 32) both apply.
    assert result.score == 18
    titles = {f.title for f in result.findings}
    assert "Threat feed flag" in titles
    assert "External threat intelligence flag" in titles