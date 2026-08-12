"""F3 hardening: unexpected provider exceptions degrade to *unavailable*.

A provider that raises (bad payload shape, adapter bug, unexpected HTTP
stack error) must never:

- break the scan (no error module, no HTTP 500),
- turn into a malicious / critical finding, or
- change the risk score beyond the established unavailable semantics.

Every test is hermetic: adapters are stubs, no live API, no API keys.
"""

from app.modules.threatintel.adapters.base import ThreatIntelAdapter
from app.modules.threatintel.scanner import scan_threatintel_module
from app.schemas.threat_intel import ThreatIntelSignals


def malicious_signal(provider: str) -> ThreatIntelSignals:
    return ThreatIntelSignals(
        provider=provider,
        status="available",
        malicious=True,
        suspicious=False,
        detections=1,
        categories=["malware"],
        confidence=90,
    )


class RaisingAdapter(ThreatIntelAdapter):
    provider = "raising-provider"

    def lookup(self, target: str) -> ThreatIntelSignals:
        raise RuntimeError("simulated unexpected provider failure")


class WorkingAdapter(ThreatIntelAdapter):
    provider = "working-provider"

    def __init__(self, signal: ThreatIntelSignals) -> None:
        super().__init__()
        self._signal = signal

    def lookup(self, target: str) -> ThreatIntelSignals:
        return self._signal


def _signals(result) -> list[dict]:
    return result.details["external_threat_intel"]


def test_unexpected_provider_exception_becomes_unavailable_signal():
    result = scan_threatintel_module("x.test", adapters=[RaisingAdapter()])

    assert result.status != "error"
    signals = _signals(result)
    assert len(signals) == 1
    assert signals[0]["status"] == "unavailable"
    assert signals[0]["reason"] == "bad_response"
    assert signals[0]["malicious"] is False
    assert signals[0]["suspicious"] is False


def test_provider_exception_produces_no_malicious_finding():
    result = scan_threatintel_module("x.test", adapters=[RaisingAdapter()])

    titles = [finding.title for finding in result.findings]
    assert "External threat intelligence unavailable" in titles
    assert not any(finding.severity in {"high", "critical"} for finding in result.findings)


def test_provider_exception_does_not_change_score():
    baseline = scan_threatintel_module("x.test", adapters=None)
    result = scan_threatintel_module("x.test", adapters=[RaisingAdapter()])

    assert result.score == baseline.score == 100
    assert result.status == baseline.status


def test_exception_and_verdict_from_two_providers_are_isolated():
    adapters = [RaisingAdapter(), WorkingAdapter(malicious_signal("working-provider"))]
    result = scan_threatintel_module("x.test", adapters=adapters)

    by_provider = {signal["provider"]: signal for signal in _signals(result)}
    assert by_provider["raising-provider"]["status"] == "unavailable"
    assert by_provider["working-provider"]["status"] == "available"
    assert by_provider["working-provider"]["malicious"] is True

    assert result.score < 100
    titles = [finding.title for finding in result.findings]
    assert "External threat intelligence flag" in titles

    correlation = result.details["threat_intel_correlation"]
    assert correlation["available_count"] == 1
    assert correlation["unavailable_count"] == 1