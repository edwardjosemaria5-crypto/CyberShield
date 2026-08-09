"""Explanation tests for threat-intelligence findings.

Every provider finding MUST carry a deterministic ``explanation`` field built
only from the normalized signal: WHAT was reported, WHO reported it, WHAT
evidence exists, HOW confident the signal is, and WHY it affected risk.
Explanations never use AI and never contain credentials.
"""

from app.modules.threatintel.adapters.base import ThreatIntelAdapter
from app.modules.threatintel.scanner import scan_threatintel_module
from app.schemas.threat_intel import ThreatIntelSignals

SECRET_KEY = "AIza-super-secret-key-that-must-not-leak"


class StubAdapter(ThreatIntelAdapter):
    def __init__(self, signal: ThreatIntelSignals):
        super().__init__(api_key=SECRET_KEY)
        self._signal = signal

    def lookup(self, target: str) -> ThreatIntelSignals:
        return self._signal


def _scan(signal: ThreatIntelSignals) -> list:
    result = scan_threatintel_module("x.test", adapters=[StubAdapter(signal)])
    return result.findings


def _malicious_signal(confidence: int = 90) -> ThreatIntelSignals:
    return ThreatIntelSignals(
        provider="google-safe-browsing",
        status="available",
        malicious=True,
        suspicious=False,
        detections=2,
        categories=["malware", "social-engineering"],
        confidence=confidence,
        evidence=["MALWARE match on 300s", "SOCIAL_ENGINEERING match on 300s"],
    )


def _suspicious_signal(confidence: int = 70) -> ThreatIntelSignals:
    return ThreatIntelSignals(
        provider="google-safe-browsing",
        status="available",
        malicious=False,
        suspicious=True,
        detections=1,
        categories=["social-engineering"],
        confidence=confidence,
        evidence=["SOCIAL_ENGINEERING match"],
    )


# ------------------------------------------------------------- explanation

def test_malicious_finding_has_non_empty_explanation():
    findings = _scan(_malicious_signal(90))
    malicious_finding = [f for f in findings if f.title == "External threat intelligence flag"][0]
    assert malicious_finding.explanation
    assert malicious_finding.explanation.strip()


def test_suspicious_finding_has_non_empty_explanation():
    findings = _scan(_suspicious_signal(70))
    suspicious_finding = [f for f in findings if f.title == "External threat intelligence suspicion"][0]
    assert suspicious_finding.explanation
    assert suspicious_finding.explanation.strip()


def test_clean_result_explanation_is_accurate():
    clean_signal = ThreatIntelSignals(
        provider="stub-provider",
        status="available",
        malicious=False,
        suspicious=False,
        detections=0,
        categories=[],
        confidence=90,
    )
    findings = _scan(clean_signal)
    clean_finding = [f for f in findings if f.title == "External threat intelligence clean result"][0]
    explanation = clean_finding.explanation
    assert "no threat" in explanation.lower()
    # Must NOT claim the domain is globally safe; the disclaimer itself must
    # say the opposite (single-provider cleanliness proves nothing).
    assert "does not prove the domain is globally safe" in explanation.lower()


def test_provider_unavailable_explanation_is_neutral():
    unavailable = ThreatIntelSignals(provider="stub-provider", status="unavailable", reason="timeout")
    findings = _scan(unavailable)
    failed_finding = [f for f in findings if f.title == "External threat intelligence unavailable"][0]
    explanation = failed_finding.explanation.lower()
    assert "could not" in explanation
    assert "no threat determination" in explanation
    # Failure must NOT imply maliciousness.
    assert "malicious" not in explanation


def test_explanation_includes_provider():
    findings = _scan(_malicious_signal())
    malicious_finding = [f for f in findings if f.title == "External threat intelligence flag"][0]
    assert "google-safe-browsing" in malicious_finding.explanation


def test_explanation_does_not_invent_evidence():
    no_evidence = ThreatIntelSignals(
        provider="stub-provider",
        status="available",
        malicious=True,
        suspicious=False,
        detections=1,
        categories=["malware"],
        confidence=90,
        evidence=[],
    )
    findings = _scan(no_evidence)
    finding = [f for f in findings if f.title == "External threat intelligence flag"][0]
    explanation = finding.explanation.lower()
    assert "no specific evidence" in explanation


def test_explanation_does_not_contain_api_credentials():
    findings = _scan(_malicious_signal())
    for finding in findings:
        assert SECRET_KEY not in finding.explanation
        assert SECRET_KEY not in finding.evidence
        assert SECRET_KEY not in finding.description