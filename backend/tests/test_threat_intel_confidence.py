"""Confidence-model tests for threat-intelligence scoring.

The model (see ``app/modules/threatintel/rules.py``):

    penalty = round_half_up(base_penalty * signal.confidence / 100)

- base_penalty: 35 for malicious, 15 for suspicious
- confidence valid range 0-100, validated by the schema, clamped defensively
- clean / unavailable signals always contribute 0
- summed provider penalties are capped at PROVIDER_PENALTY_CAP (40)
"""

import pytest
from pydantic import ValidationError

from app.modules.threatintel.adapters.base import ThreatIntelAdapter
from app.modules.threatintel.scanner import scan_threatintel_module
from app.schemas.module_result import ModuleResult
from app.schemas.threat_intel import ThreatIntelSignals
from app.risk_engine.scorer import compute_trust_score


class StubAdapter(ThreatIntelAdapter):
    """Deterministic adapter stub returning one fixed signal."""

    def __init__(self, signal: ThreatIntelSignals, configured: bool = True):
        super().__init__(api_key="key" if configured else None)
        self._signal = signal

    def lookup(self, target: str) -> ThreatIntelSignals:
        return self._signal


def malicious(confidence: int | None = None) -> ThreatIntelSignals:
    kwargs = {
        "provider": "stub-adapter",
        "status": "available",
        "malicious": True,
        "categories": ["malware"],
        "evidence": ["MALWARE match"],
    }
    if confidence is not None:
        kwargs["confidence"] = confidence
    return ThreatIntelSignals(**kwargs)


def clean(confidence: int) -> ThreatIntelSignals:
    return ThreatIntelSignals(
        provider="stub-adapter",
        status="available",
        malicious=False,
        suspicious=False,
        detections=0,
        categories=[],
        confidence=confidence,
    )


def _scan(signal: ThreatIntelSignals) -> ModuleResult:
    return scan_threatintel_module("x.test", adapters=[StubAdapter(signal)])


# ------------------------------------------------------- penalty scaling

def test_high_confidence_malicious_has_greatest_impact():
    result = _scan(malicious(confidence=90))
    assert result.score == 68  # 100 - round_half_up(35*0.9)=32


def test_medium_confidence_malicious_has_medium_impact():
    result = _scan(malicious(confidence=50))
    assert result.score == 82  # 100 - round_half_up(35*0.5)=18


def test_low_confidence_malicious_has_lowest_impact():
    result = _scan(malicious(confidence=20))
    assert result.score == 93  # 100 - round_half_up(35*0.2)=7


def test_high_confidence_clean_never_penalizes():
    result = _scan(clean(95))
    assert result.score == 100
    assert not any(f.severity in {"critical", "high", "medium"} for f in result.findings)


def test_low_confidence_clean_never_penalizes():
    result = _scan(clean(5))
    assert result.score == 100


def test_provider_unavailable_never_penalizes():
    unavailable = ThreatIntelSignals(provider="stub", status="unavailable", reason="timeout")
    result = _scan(unavailable)
    assert result.score == 100


def test_malicious_without_confidence_contributes_nothing():
    """Confidence defaults to 0; we never guess a certainty the provider
    did not supply, so no penalty applies — but the finding still exists."""
    result = _scan(malicious())
    assert result.score == 100
    assert any("no reported confidence" in f.explanation for f in result.findings)


def test_invalid_confidence_is_rejected_by_schema():
    with pytest.raises(ValidationError):
        ThreatIntelSignals(provider="stub", malicious=True, confidence=150)
    with pytest.raises(ValidationError):
        ThreatIntelSignals(provider="stub", malicious=True, confidence=-5)


def test_multiple_provider_detections_are_capped():
    """Two malicious providers must not multiply beyond PROVIDER_PENALTY_CAP."""
    result = scan_threatintel_module(
        "x.test",
        adapters=[StubAdapter(malicious(confidence=90)), StubAdapter(malicious(confidence=90))],
    )
    # Raw sum 32+32=64 -> capped at 40 -> score 60.
    assert result.score == 60


def test_threat_intel_combines_with_other_risk_signals():
    """Threat result lowers the aggregated trust score relative to a clean
    threat result, alongside an independent weak signal."""
    threat_bad = scan_threatintel_module("x.test", adapters=[StubAdapter(malicious(confidence=90))])
    threat_clean = scan_threatintel_module("x.test", adapters=[StubAdapter(clean(95))])
    dns_result = ModuleResult(module="dns", score=100, confidence=100)

    with_threat = compute_trust_score({"threatintel": threat_bad, "dns": dns_result}).score
    without_threat = compute_trust_score({"threatintel": threat_clean, "dns": dns_result}).score

    # Threat evidence pulls the aggregate score below the clean-threat baseline,
    # and the dns signal still contributes independently.
    assert with_threat < without_threat