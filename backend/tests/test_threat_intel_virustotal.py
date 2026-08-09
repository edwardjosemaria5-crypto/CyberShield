"""Tests for the VirusTotal adapter and two-provider correlation.

Every external call is mocked with httpx.MockTransport — no live API, no
real keys. Coverage follows the milestone contract:

- adapter: malicious / clean / suspicious / unavailable / timeout / HTTP
  error / malformed response / invalid key / no-analysis (404)
- correlation with both providers: agreement, conflict, unavailable
  combinations, confidence aggregation, bonus/multiplier mechanics
- scanner integration: provider findings preserved, aggregate finding
  supplements, score boundaries, evidence deduplication
"""

import httpx
import pytest

from app.modules.threatintel.adapters import build_adapters
from app.modules.threatintel.adapters.base import ThreatIntelAdapter
from app.modules.threatintel.adapters.virustotal import ENDPOINT, VirusTotalAdapter
from app.modules.threatintel.correlation import correlate_threat_signals
from app.modules.threatintel.scanner import scan_threatintel_module
from app.schemas.threat_intel import ThreatIntelSignals

API_KEY = "test-vt-key-not-a-real-key"


def vt_payload(stats: dict, results: dict | None = None, reputation=None, **extra) -> dict:
    attributes = {
        "last_analysis_stats": stats,
        "last_analysis_results": results or {},
        "reputation": reputation,
    }
    attributes.update(extra)
    return {"data": {"type": "url", "id": "x", "attributes": attributes}}


def json_response(payload: dict, status: int = 200) -> httpx.Response:
    return httpx.Response(status, json=payload, request=httpx.Request("GET", f"{ENDPOINT}/u"))


def make_adapter(handler) -> VirusTotalAdapter:
    return VirusTotalAdapter(
        api_key=API_KEY,
        timeout_seconds=1.0,
        transport=httpx.MockTransport(handler),
    )


CLEAN_STATS = {"malicious": 0, "suspicious": 0, "harmless": 20, "undetected": 30}


# ------------------------------------------------------------- basic lookup

def test_clean_analysis_is_not_a_threat():
    adapter = make_adapter(lambda request: json_response(vt_payload(CLEAN_STATS)))

    signals = adapter.lookup("https://example.com")

    assert signals.status == "available"
    assert signals.malicious is False
    assert signals.suspicious is False
    assert signals.detections == 0
    assert signals.categories == []
    assert signals.confidence == 0


def test_malicious_count_maps_to_malicious():
    stats = {"malicious": 1, "suspicious": 0, "harmless": 4, "undetected": 45}
    results = {"Bitdefender": {"category": "malicious", "result": "Phishing URL"}}
    adapter = make_adapter(lambda request: json_response(vt_payload(stats, results)))

    signals = adapter.lookup("evil.example.com")

    assert signals.status == "available"
    assert signals.malicious is True
    assert signals.suspicious is False
    assert signals.detections == 1
    assert "phishing" in signals.categories
    # 30 + 15*1 + 10*0
    assert signals.confidence == 45
    assert any("Engine tally" in item for item in signals.evidence)


def test_suspicious_only_is_suspicious_not_malicious():
    stats = {"malicious": 0, "suspicious": 3, "harmless": 10, "undetected": 37}
    results = {"Emsisoft": {"category": "suspicious", "result": "risky downloader"}}
    adapter = make_adapter(lambda request: json_response(vt_payload(stats, results)))

    signals = adapter.lookup("risky.example.com")

    assert signals.status == "available"
    assert signals.malicious is False
    assert signals.suspicious is True
    assert signals.detections == 3
    # 30 + 10*3
    assert signals.confidence == 60


def test_malicious_plus_suspicious_keeps_both_flags():
    stats = {"malicious": 4, "suspicious": 1, "harmless": 1, "undetected": 44}
    adapter = make_adapter(lambda request: json_response(vt_payload(stats)))

    signals = adapter.lookup("evil.example.com")

    assert signals.malicious is True
    assert signals.suspicious is True
    assert signals.detections == 5
    # 30 + 15*4 + 10*1 -> caps at 100.
    assert signals.confidence == 100


def test_high_counts_clamp_confidence():
    stats = {"malicious": 99, "suspicious": 99, "harmless": 0, "undetected": 0}
    adapter = make_adapter(lambda request: json_response(vt_payload(stats)))

    signals = adapter.lookup("evil.example.com")

    assert signals.confidence == 100


# ------------------------------------------------------------ no-analysis

def test_missing_record_404_is_unavailable_not_clean():
    payload = {"error": {"code": "ResourceNotFoundException"}}
    adapter = make_adapter(lambda request: json_response(payload, status=404))

    signals = adapter.lookup("never-analysed.example.com")

    assert signals.status == "unavailable"
    assert signals.reason == "no_analysis"
    assert signals.malicious is False
    assert signals.suspicious is False
    assert signals.confidence == 0


def test_unrecognized_404_body_is_bad_response():
    adapter = make_adapter(lambda request: json_response({}, status=404))

    signals = adapter.lookup("weird.example.com")

    assert signals.status == "unavailable"
    assert signals.reason == "bad_response"


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


# ------------------------------------------------------------- bad payloads

def test_non_json_body_is_bad_response():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=b"<html>no</html>", request=request)

    adapter = make_adapter(handler)

    signals = adapter.lookup("example.com")

    assert signals.status == "unavailable"
    assert signals.reason == "bad_response"


def test_missing_attributes_is_bad_response():
    adapter = make_adapter(
        lambda request: json_response({"data": {"type": "url"}})
    )

    signals = adapter.lookup("example.com")

    assert signals.status == "unavailable"
    assert signals.reason == "bad_response"


def test_missing_stats_is_bad_response():
    adapter = make_adapter(
        lambda request: json_response({"data": {"attributes": {"nope": 1}}})
    )

    signals = adapter.lookup("example.com")

    assert signals.status == "unavailable"
    assert signals.reason == "bad_response"


# ------------------------------------------------------------------ config

def test_engine_verdict_without_result_text_still_counts():
    stats = {"malicious": 2, "suspicious": 0, "harmless": 0, "undetected": 55}
    results = {"VendorX": {"category": "malicious"}}
    adapter = make_adapter(lambda request: json_response(vt_payload(stats, results)))

    signals = adapter.lookup("x.example.com")

    assert signals.malicious is True
    assert signals.detections == 2
    assert "VendorX" in signals.evidence[1]


def test_missing_api_key_is_unavailable():
    adapter = VirusTotalAdapter(api_key=None)

    signals = adapter.lookup("example.com")

    assert signals.status == "unavailable"
    assert signals.reason == "missing_api_key"


def test_invalid_target_is_unavailable():
    adapter = make_adapter(lambda request: json_response(vt_payload(CLEAN)))

    signals = adapter.lookup("this is not a url")

    assert signals.status == "unavailable"
    assert signals.reason == "invalid_target"


def test_build_adapters_skips_unconfigured_virustotal():
    adapters = build_adapters(google_safe_browsing_api_key=API_KEY)
    assert len(adapters) == 1
    assert not isinstance(adapters[0], VirusTotalAdapter)


def test_build_adapters_includes_both_configured_providers():
    adapters = build_adapters(
        google_safe_browsing_api_key=API_KEY,
        virus_total_api_key=API_KEY,
    )
    assert len(adapters) == 2
    assert isinstance(adapters[0], ThreatIntelAdapter)
    assert isinstance(adapters[1], VirusTotalAdapter)


# ------------------------------------------------------------ helpers used
# below: stub signals with real provider slugs + a stub adapter


def _signal(provider: str, **overrides) -> ThreatIntelSignals:
    base: dict = {
        "provider": provider,
        "status": "available",
        "malicious": False,
        "suspicious": False,
        "confidence": 0,
    }
    base.update(overrides)
    return ThreatIntelSignals(**base)


def gsb_malicious(confidence: int = 90) -> ThreatIntelSignals:
    return _signal(
        "google-safe-browsing",
        malicious=True,
        confidence=confidence,
        categories=["malware"],
        evidence=["MALWARE match"],
    )


def vt_malicious(confidence: int = 75) -> ThreatIntelSignals:
    return _signal(
        "virus_total",
        malicious=True,
        confidence=confidence,
        categories=["malware"],
        evidence=["Engine tally: 5 malicious, 0 suspicious, 0 harmless, 40 undetected"],
    )


def vt_clean(confidence: int = 0) -> ThreatIntelSignals:
    return _signal("virus_total", confidence=confidence)


class StubAdapter(ThreatIntelAdapter):
    def __init__(self, stub_signal: ThreatIntelSignals, configured: bool = True):
        self.signal = stub_signal
        self.configured = configured

    @property
    def is_configured(self) -> bool:
        return self.configured

    def lookup(self, target: str) -> ThreatIntelSignals:
        return self.signal


def _scan(*signals: ThreatIntelSignals):
    return scan_threatintel_module("x.test", adapters=[StubAdapter(s) for s in signals])


# --------------------------------------------------------- two-provider correlation

def test_two_providers_agree_malicious():
    result = correlate_threat_signals([gsb_malicious(), vt_malicious()])

    assert result.available_count == 2
    assert result.malicious_count == 2
    assert result.clean_count == 0
    assert result.agreement == "consistent"
    assert result.consensus == "malicious"
    assert result.conflict is False
    # max(90,75)=90 + agreement bonus 10 -> 100 (capped).
    assert result.malicious_confidence == 100


def test_two_providers_agree_clean():
    result = correlate_threat_signals([_signal("google-safe-browsing"), vt_clean()])

    assert result.available_count == 2
    assert result.clean_count == 2
    assert result.agreement == "consistent"
    assert result.consensus == "clean"
    assert result.malicious_confidence == 0


def test_google_malicious_viral_clean_is_a_conflict():
    result = correlate_threat_signals([gsb_malicious(), vt_clean()])

    assert result.conflict is True
    assert result.agreement == "conflict"
    assert result.consensus == "conflict"
    assert result.clean_count == 1
    assert result.malicious_count == 1
    # max 90 + 0 bonus = 90; conflict multiplier 0.85 -> 76.5 -> 77.
    assert result.malicious_confidence == 77


def test_google_clean_vs_vt_malicious_is_a_conflict():
    result = correlate_threat_signals([_signal("google-safe-browsing"), vt_malicious()])

    assert result.conflict is True
    assert result.consensus == "conflict"
    assert result.malicious_count == 1
    assert result.clean_count == 1


def test_unavailable_plus_malicious_is_not_a_conflict():
    unavailable = _signal(
        "virus_total",
        status="unavailable",
        reason="network",
        evidence=["The provider could not be reached."],
    )
    result = correlate_threat_signals([gsb_malicious(), unavailable])

    assert result.unavailable_count == 1
    assert result.available_count == 1
    # Unavailable must NOT vote against the available malicious verdict.
    assert result.conflict is False
    assert result.agreement == "consistent"
    assert result.consensus == "malicious"
    assert result.malicious_confidence == 90


def test_unavailable_plus_clean_stays_clean():
    unavailable = _signal("virus_total", status="unavailable", reason="timeout")
    result = correlate_threat_signals([_signal("google-safe-browsing"), unavailable])

    assert result.unavailable_count == 1
    assert result.available_count == 1
    assert result.clean_count == 1
    assert result.consensus == "clean"
    assert result.conflict is False


def test_different_confidences_use_the_strongest():
    weak = gsb_malicious(confidence=20)
    strong = vt_malicious(confidence=85)
    result = correlate_threat_signals([weak, strong])

    # base = max(20, 85) = 85 + 10 agreement bonus -> 95.
    assert result.malicious_confidence == 95


def test_conflict_multiplier_from_config():
    result = correlate_threat_signals(
        [gsb_malicious(), vt_clean()],
        conflict_multiplier=0.5,
    )

    assert result.conflict is True
    assert result.malicious_confidence == 45  # 90 * 0.5


def test_agreement_bonus_from_config():
    result = correlate_threat_signals(
        [gsb_malicious(), vt_malicious()],
        agreement_bonus=5,
    )

    # max(90,75) + 5*(2-1) = 95.
    assert result.malicious_confidence == 95


def test_score_boundary_provider_caps_penalty():
    result = _scan(gsb_malicious(), vt_malicious())

    # Both malicious at high confidence; provider penalties are capped at
    # PROVIDER_PENALTY_CAP (40) in total — score cannot drop below 60 from
    # external signals alone.
    assert result.score == 60


# ----------------------------------------------------- scanner integration

def test_scanner_preserves_both_provider_findings():
    result = _scan(gsb_malicious(), vt_malicious())

    titles = [f.title for f in result.findings]
    providers = [s["provider"] for s in result.details["external_threat_intel"]]

    assert providers == ["google-safe-browsing", "virus_total"]
    # both provider findings + the supplemented aggregate finding.
    assert titles.count("External threat intelligence flag") == 2
    assert "Correlated threat intelligence verdict" in titles


def test_scanner_aggregate_finding_supplements_not_replaces():
    result = _scan(gsb_malicious(), vt_malicious())

    signals = result.details["external_threat_intel"]
    assert len(signals) == 2
    assert all(s["malicious"] for s in signals)
    assert result.details["threat_intel_correlation"]["consensus"] == "malicious"


def test_duplicate_evidence_is_deduplicated_in_correlation():
    duplicate_evidence = ["MALWARE match"]
    first = gsb_malicious()
    # A second *provider* with an identical/overlapping evidence string.
    v = _signal(
        "virus_total",
        malicious=True,
        confidence=75,
        evidence=["MALWARE match"],
    )
    result = correlate_threat_signals([first, v])

    assert len(result.evidence) == 1


def test_one_provider_only_passes_through_unchanged():
    result = correlate_threat_signals([gsb_malicious()])

    assert result.available_count == 1
    assert result.malicious_count == 1
    assert result.conflict is False
    assert result.malicious_confidence == 90


def test_correlation_is_provider_name_agnostic():
    """The engine must not branch on provider names."""
    a = _signal("provider-a", malicious=True, confidence=60)
    b = _signal("provider-b", confidence=0)
    result = correlate_threat_signals([a, b])

    assert result.conflict is True
    assert result.agreement == "conflict"