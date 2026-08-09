"""Multi-provider threat-intelligence correlation tests.

Covers the provider-independent correlation engine
(``app.modules.threatintel.correlation``), its integration into the
threatintel scanner (aggregate finding SUPPLEMENTS provider findings), and
the bounded environment configuration.

Model under test (see ``correlation.py``):

    malicious_confidence = max(confidence over malicious signals)
                           + AGREEMENT_BONUS * (malicious_count - 1)
                           * CONFLICT_MULTIPLIER     if conflict
                           clamped to [0, 100]

- provider unavailability is never a verdict and never a conflict
- agreement/conflict only shape confidence, never classifications
- every scanner test uses stub adapters -- no network, no real keys
"""

import importlib

import pytest
from pydantic import ValidationError

import app.core.config as config
from app.modules.threatintel.adapters.base import ThreatIntelAdapter
from app.modules.threatintel.correlation import correlate_threat_signals
from app.modules.threatintel.scanner import scan_threatintel_module
from app.schemas.threat_intel import ThreatIntelSignals

BONUS = 10
MULTIPLIER = 0.85


# ------------------------------------------------------------- fixtures

def signal(
    provider: str,
    malicious: bool = False,
    suspicious: bool = False,
    confidence: int = 0,
    categories: list[str] | None = None,
    evidence: list[str] | None = None,
    status: str = "available",
    reason: str = "network",
) -> ThreatIntelSignals:
    return ThreatIntelSignals(
        provider=provider,
        status=status,
        reason=reason,
        malicious=malicious,
        suspicious=suspicious,
        detections=len(categories or []),
        categories=categories or [],
        confidence=confidence,
        evidence=evidence or [],
    )


def clean(provider: str, confidence: int = 95) -> ThreatIntelSignals:
    return signal(provider, confidence=confidence)


def malicious(provider: str, confidence: int = 90) -> ThreatIntelSignals:
    return signal(provider, malicious=True, confidence=confidence, categories=["malware"])


def suspicious(provider: str, confidence: int = 60) -> ThreatIntelSignals:
    return signal(
        provider, suspicious=True, confidence=confidence, categories=["social-engineering"]
    )


def unavailable(provider: str) -> ThreatIntelSignals:
    return signal(provider, status="unavailable", reason="timeout")


class StubAdapter(ThreatIntelAdapter):
    """Deterministic adapter returning one fixed signal (no network)."""

    def __init__(self, stub_signal: ThreatIntelSignals):
        super().__init__(api_key="stub-key")
        self._stub = stub_signal

    def lookup(self, target: str) -> ThreatIntelSignals:
        return self._stub


# --------------------------------------------------------- basic outcomes

def test_all_three_providers_clean():
    result = correlate_threat_signals([clean("a"), clean("b"), clean("c")], BONUS, MULTIPLIER)
    assert result.consensus == "clean"
    assert result.agreement == "consistent"
    assert result.clean_count == 3
    assert result.malicious_count == 0
    assert result.conflict is False
    assert result.malicious_confidence == 0
    assert result.suspicious_confidence == 0


def test_one_malicious_provider_is_enough_for_a_verdict():
    result = correlate_threat_signals([malicious("a")], BONUS, MULTIPLIER)
    assert result.consensus == "malicious"
    assert result.agreement == "consistent"
    assert result.malicious_count == 1
    assert result.conflict is False
    assert result.malicious_confidence == 90  # no bonus, no discount


def test_single_malicious_among_clean_is_a_conflict():
    result = correlate_threat_signals([clean("a"), malicious("b"), clean("c")], BONUS, MULTIPLIER)
    assert result.consensus == "conflict"
    assert result.agreement == "conflict"
    assert result.malicious_count == 1
    assert result.clean_count == 2
    assert result.conflict is True


def test_two_malicious_providers():
    result = correlate_threat_signals([malicious("a"), malicious("b")], BONUS, MULTIPLIER)
    assert result.consensus == "malicious"
    assert result.agreement == "consistent"
    assert result.malicious_count == 2
    assert result.conflict is False
    assert result.malicious_confidence == 100  # 90 + bonus, clamped


def test_all_providers_malicious():
    result = correlate_threat_signals(
        [malicious("a"), malicious("b"), malicious("c")], BONUS, MULTIPLIER
    )
    assert result.consensus == "malicious"
    assert result.agreement == "consistent"
    assert result.malicious_count == 3
    assert result.conflict is False
    assert result.malicious_confidence == 100  # 90 + 2*10, clamped


# ------------------------------------------------------------ conflict

def test_malicious_plus_clean_is_a_conflict():
    result = correlate_threat_signals([malicious("a"), clean("b")], BONUS, MULTIPLIER)
    assert result.conflict is True
    assert result.agreement == "conflict"
    assert result.consensus == "conflict"
    assert result.malicious_count == 1
    assert result.clean_count == 1


def test_conflict_discount_is_applied_to_confidence():
    result = correlate_threat_signals([malicious("a", confidence=80), clean("b")], BONUS, MULTIPLIER)
    assert result.conflict is True
    assert result.malicious_confidence == 68  # 80 * 0.85
    assert result.suspicious_confidence == 0


def test_malicious_plus_unavailable_is_NOT_a_conflict():
    result = correlate_threat_signals([malicious("a"), unavailable("b")], BONUS, MULTIPLIER)
    assert result.conflict is False
    assert result.agreement == "consistent"
    assert result.consensus == "malicious"
    assert result.unavailable_count == 1
    assert result.malicious_count == 1
    assert result.malicious_confidence == 90  # absence never discounts


def test_clean_plus_unavailable_is_NOT_a_conflict():
    result = correlate_threat_signals([clean("a"), unavailable("b")], BONUS, MULTIPLIER)
    assert result.conflict is False
    assert result.agreement == "consistent"
    assert result.consensus == "clean"
    assert result.clean_count == 1
    assert result.unavailable_count == 1


def test_suspicious_plus_clean_is_partial_not_conflict():
    result = correlate_threat_signals([suspicious("a"), clean("b")], BONUS, MULTIPLIER)
    assert result.conflict is False
    assert result.agreement == "partial"
    # Caution-priority consensus: any flagged source wins over a clean
    # result, but the disagreement is preserved (partial, not unresolved).
    assert result.consensus == "suspicious"
    assert result.suspicious_count == 1
    assert result.clean_count == 1
    assert result.suspicious_confidence == 60  # no discount on suspicion


# ---------------------------------------------------------- confidence

def test_confidence_uses_strongest_provider_not_average():
    result = correlate_threat_signals(
        [malicious("a", confidence=30), malicious("b", confidence=90)], BONUS, MULTIPLIER
    )
    assert result.malicious_confidence == 100  # max(90) + bonus, NOT the mean (60)
    assert result.malicious_count == 2


def test_agreement_bonus_only_with_second_agreeing_provider():
    single = correlate_threat_signals([malicious("a", confidence=50)], BONUS, MULTIPLIER)
    paired = correlate_threat_signals(
        [malicious("a", confidence=50), malicious("b", confidence=50)], BONUS, MULTIPLIER
    )
    assert single.malicious_confidence == 50
    assert paired.malicious_confidence == 60  # 50 + 10


def test_agreement_bonus_skipped_when_no_confidence_supplied():
    result = correlate_threat_signals(
        [malicious("a", confidence=0), malicious("b", confidence=0)], BONUS, MULTIPLIER
    )
    assert result.malicious_count == 2
    assert result.malicious_confidence == 0  # never invent provider certainty


def test_agreeing_providers_respect_the_100_boundary():
    result = correlate_threat_signals(
        [
            malicious("a", confidence=100),
            malicious("b", confidence=100),
            malicious("c", confidence=100),
        ],
        BONUS,
        MULTIPLIER,
    )
    assert result.malicious_confidence == 100  # raw 120, clamped


def test_conflict_boundary_never_negative():
    result = correlate_threat_signals([malicious("a", confidence=10), clean("b")], BONUS, MULTIPLIER)
    assert result.conflict is True
    assert 0 <= result.malicious_confidence <= 10


def test_suspicious_confidence_aggregation():
    result = correlate_threat_signals(
        [suspicious("a", confidence=60), suspicious("b", confidence=60)], BONUS, MULTIPLIER
    )
    assert result.suspicious_confidence == 70
    assert result.consensus == "suspicious"
    assert result.suspicious_count == 2


# ---------------------------------------------------- edge / provenance

def test_no_provider_results():
    result = correlate_threat_signals([], BONUS, MULTIPLIER)
    assert result.provider_count == 0
    assert result.available_count == 0
    assert result.agreement == "none"
    assert result.consensus == "unavailable"
    assert result.malicious_confidence == 0
    assert result.conflict is False


def test_duplicate_provider_results_collapse_to_one():
    result = correlate_threat_signals([malicious("a"), clean("a")], BONUS, MULTIPLIER)
    assert result.provider_count == 1
    assert result.malicious_count == 1
    assert result.clean_count == 0
    assert result.conflict is False


def test_evidence_and_categories_are_deduplicated():
    result = correlate_threat_signals(
        [
            signal(
                "a",
                malicious=True,
                confidence=90,
                categories=["malware", "phishing"],
                evidence=["MALWARE match"],
            ),
            signal(
                "b",
                malicious=True,
                confidence=90,
                categories=["malware"],
                evidence=["MALWARE match"],
            ),
        ],
        BONUS,
        MULTIPLIER,
    )
    assert result.malicious_confidence == 100  # 90 + bonus; agreement is real
    assert result.categories == ["malware", "phishing"]
    assert result.evidence == ["MALWARE match"]


def test_result_is_order_independent():
    """Aggregation fields must not depend on input order. The `signals`
    provenance list keeps first-occurrence order by design."""
    signals = [malicious("a"), clean("b"), suspicious("c")]
    forward = correlate_threat_signals(signals, BONUS, MULTIPLIER)
    backward = correlate_threat_signals(list(reversed(signals)), BONUS, MULTIPLIER)
    assert forward.model_dump(exclude={"signals"}) == backward.model_dump(exclude={"signals"})
    assert [s.provider for s in forward.signals] == ["a", "b", "c"]


def test_invalid_confidence_is_rejected_by_schema():
    with pytest.raises(ValidationError):
        ThreatIntelSignals(provider="stub", malicious=True, confidence=150)
    with pytest.raises(ValidationError):
        ThreatIntelSignals(provider="stub", malicious=True, confidence=-5)


def test_provider_failure_never_punishes():
    result = correlate_threat_signals([unavailable("a"), unavailable("b")], BONUS, MULTIPLIER)
    assert result.consensus == "unavailable"
    assert result.agreement == "none"
    assert result.unavailable_count == 2
    assert result.malicious_confidence == 0


# ------------------------------------------------ scanner integration

def _scan(*stub_signals: ThreatIntelSignals):
    return scan_threatintel_module("x.test", adapters=[StubAdapter(s) for s in stub_signals])


def test_aggregate_finding_generated():
    result = _scan(malicious("a"), clean("b"))
    titles = [f.title for f in result.findings]
    assert any("Correlat" in title for title in titles)
    assert any(title == "External threat intelligence flag" for title in titles)


def test_provider_specific_findings_preserved():
    result = _scan(malicious("a"), clean("b"))
    title_map = {f.title: f for f in result.findings}
    flag = title_map["External threat intelligence flag"]
    clean_finding = title_map["External threat intelligence clean result"]
    assert "a" in flag.explanation
    assert "b" in clean_finding.explanation


def test_aggregate_finding_names_agreeing_providers():
    result = _scan(malicious("a"), malicious("b"))
    aggregate = [f for f in result.findings if f.title == "Correlated threat intelligence verdict"][0]
    assert aggregate.severity == "critical"  # confidence 100
    assert aggregate.confidence == 100
    assert "strong agreement" in aggregate.explanation
    assert "2 of 2" in aggregate.description


def test_aggregate_finding_preserves_conflict():
    result = _scan(malicious("a", confidence=80), clean("b"))
    title_map = {f.title: f for f in result.findings}
    aggregate = title_map["Correlated threat intelligence: conflicting verdicts"]
    assert aggregate.confidence == 68  # 80 * 0.85
    assert aggregate.severity == "high"  # below the critical ladder; contested
    assert "disagreed" in aggregate.explanation
    assert "no threat match" in aggregate.description


def test_no_providers_emits_no_threat_findings():
    result = scan_threatintel_module("x.test", adapters=None)
    assert result.score == 100
    assert not any("External threat intelligence" in f.title for f in result.findings)
    assert not any("Correlat" in f.title for f in result.findings)


def test_all_providers_failed_is_neutral():
    result = _scan(unavailable("a"))
    assert result.score == 100
    # No aggregate is formed when nothing answered; the failure surfaces
    # only as the neutral per-provider info finding.
    assert len(result.findings) == 1
    assert result.findings[0].title == "External threat intelligence unavailable"
    assert result.findings[0].severity == "info"
    assert result.findings[0].confidence == 0


def test_correlation_details_exposed_in_module_result():
    result = _scan(malicious("a"), malicious("b"))
    correlation = result.details["threat_intel_correlation"]
    assert correlation["provider_count"] == 2
    assert correlation["malicious_count"] == 2
    assert correlation["consensus"] == "malicious"


# ------------------------------------------------------------ configuration

def test_config_defaults(monkeypatch):
    monkeypatch.delenv("THREAT_INTEL_AGREEMENT_BONUS", raising=False)
    monkeypatch.delenv("THREAT_INTEL_CONFLICT_MULTIPLIER", raising=False)
    importlib.reload(config)
    assert config.THREAT_INTEL_AGREEMENT_BONUS == 10
    assert config.THREAT_INTEL_CONFLICT_MULTIPLIER == 0.85


def test_config_clamps_out_of_range(monkeypatch):
    monkeypatch.setenv("THREAT_INTEL_AGREEMENT_BONUS", "999")
    monkeypatch.setenv("THREAT_INTEL_CONFLICT_MULTIPLIER", "3")
    importlib.reload(config)
    assert config.THREAT_INTEL_AGREEMENT_BONUS == 100
    assert config.THREAT_INTEL_CONFLICT_MULTIPLIER == 1.0


def test_config_falls_back_on_garbage(monkeypatch):
    monkeypatch.setenv("THREAT_INTEL_AGREEMENT_BONUS", "not-a-number")
    monkeypatch.setenv("THREAT_INTEL_CONFLICT_MULTIPLIER", "nope")
    importlib.reload(config)
    assert config.THREAT_INTEL_AGREEMENT_BONUS == 10
    assert config.THREAT_INTEL_CONFLICT_MULTIPLIER == 0.85