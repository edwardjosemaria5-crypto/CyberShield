from typing import Any

from app.core.config import THREAT_INTEL_AGREEMENT_BONUS, THREAT_INTEL_CONFLICT_MULTIPLIER
from app.modules.threatintel.adapters.base import ThreatIntelAdapter
from app.modules.threatintel.blacklist import get_blacklist_data
from app.modules.threatintel.correlation import correlate_threat_signals
from app.modules.threatintel.malware import get_malware_data
from app.modules.threatintel.phishing import get_phishing_data
from app.schemas.finding import Finding
from app.schemas.module_result import ModuleResult, score_to_status
from app.schemas.threat_correlation import CorrelationResult
from app.schemas.threat_intel import ThreatIntelSignals
from app.utils.urls import normalize_url
from .rules import (
    CONFIDENCE_HIGH,
    CONFIDENCE_MEDIUM,
    DEFAULT_CONFIDENCE,
    FEED_FLAGGED_PENALTY,
    MALWARE_PENALTY,
    MODULE_NAME,
    PHISHING_PENALTY,
    PROVIDER_PENALTY_CAP,
    SAFE_BROWSING_MALICIOUS_PENALTY,
    SAFE_BROWSING_SUSPICIOUS_PENALTY,
)


def scan_threatintel_module(
    domain: str,
    adapters: list[ThreatIntelAdapter] | None = None,
) -> ModuleResult:
    """Scan target domain across aggregated Threat Intelligence feeds (Phishing, Malware, Blacklists).

    Local heuristics run unconditionally. External provider adapters run in
    addition when configured. A provider that is unavailable contributes no
    signal (and no penalty) — absence of provider data is never treated as a
    negative verdict.
    """
    hostname = domain.replace("https://", "").replace("http://", "").split("/")[0].split(":")[0]

    phishing_data = get_phishing_data(hostname)
    malware_data = get_malware_data(hostname)
    blacklist_data = get_blacklist_data(hostname)

    score = 100
    findings: list[Finding] = []
    details: dict[str, Any] = {
        "domain": hostname,
        "phishing_analysis": phishing_data,
        "malware_analysis": malware_data,
        "threat_feed_status": blacklist_data,
    }

    if phishing_data["is_phishing_suspect"]:
        score -= PHISHING_PENALTY
        findings.append(
            Finding(
                title="Phishing pattern detected",
                severity="high",
                description=f"Phishing keyword pattern detected ({', '.join(phishing_data['detected_keywords'])}).",
                recommendation="Avoid interacting with the domain; report it to a security team.",
            )
        )

    if malware_data["is_malware_suspect"]:
        score -= MALWARE_PENALTY
        findings.append(
            Finding(
                title="Malware pattern flagged",
                severity="critical",
                description=f"Malware host pattern flagged ({malware_data['suspicious_pattern']}).",
                recommendation="Block the domain and scan any machines that accessed it.",
            )
        )

    if blacklist_data["is_flagged"]:
        score -= FEED_FLAGGED_PENALTY
        findings.append(
            Finding(
                title="Threat feed flag",
                severity="critical",
                description="Domain listed on active global threat intelligence feed.",
                recommendation="Treat the domain as malicious until verified otherwise.",
            )
        )

    # External provider stage — additive, non-blocking. Uses the same
    # normalized target the local heuristics see so signals stay comparable.
    provider_signals: list[ThreatIntelSignals] = []
    provider_penalty = 0
    if adapters:
        normalized_target = normalize_url(hostname)
        for adapter in adapters:
            signal = adapter.lookup(normalized_target)
            provider_signals.append(signal)
            penalty = _provider_penalty(signal)
            if penalty:
                provider_penalty = min(PROVIDER_PENALTY_CAP, provider_penalty + penalty)
            findings.append(_provider_finding(signal, penalty))

        # Correlation stage: reconcile every provider into ONE
        # provider-independent picture, then layer the aggregate finding on
        # top of the per-provider findings (supplement, never replace).
        correlated = correlate_threat_signals(
            provider_signals,
            agreement_bonus=THREAT_INTEL_AGREEMENT_BONUS,
            conflict_multiplier=THREAT_INTEL_CONFLICT_MULTIPLIER,
        )
        correlation_penalty = min(PROVIDER_PENALTY_CAP, provider_penalty)
        # An aggregate is only meaningful when at least one provider
        # answered; a fully-unavailable stage emits no second finding.
        if correlated.available_count > 0:
            findings.append(_correlation_finding(correlated, correlation_penalty))
        details["threat_intel_correlation"] = correlated.model_dump()

    score -= provider_penalty
    score = max(0, min(100, score))

    details["external_threat_intel"] = [signal.model_dump() for signal in provider_signals]

    return ModuleResult(
        module=MODULE_NAME,
        status=score_to_status(score),
        score=score,
        confidence=DEFAULT_CONFIDENCE,
        findings=findings,
        details=details,
    )


def _provider_penalty(signal: ThreatIntelSignals) -> int:
    """Confidence-scaled penalty for one provider verdict.

    Model (documented in ``rules.py``): the base penalty is scaled linearly
    by the signal confidence (0-100). Clean and unavailable signals always
    yield 0 (a failed or quiet provider is NEVER a negative verdict).
    Confidence is clamped defensively so a hand-crafted signal can never
    produce an impact outside the intended range.
    """
    if signal.status != "available":
        return 0
    if signal.malicious:
        base = SAFE_BROWSING_MALICIOUS_PENALTY
    elif signal.suspicious:
        base = SAFE_BROWSING_SUSPICIOUS_PENALTY
    else:
        return 0

    confidence = max(0, min(100, signal.confidence))
    return int((base * confidence) / 100 + 0.5)  # round-half-up, deterministic


def _severity_for(signal: ThreatIntelSignals) -> str:
    """Severity reflects both the verdict and the signal's confidence.

    A low-confidence malicious match is serious but not certainty; only a
    high-confidence malicious verdict is critical.
    """
    if signal.malicious:
        if signal.confidence >= CONFIDENCE_HIGH:
            return "critical"
        if signal.confidence >= CONFIDENCE_MEDIUM:
            return "high"
        return "medium"
    # suspicious
    if signal.confidence >= CONFIDENCE_HIGH:
        return "medium"
    return "low"


def _confidence_phrase(confidence: int) -> str:
    if confidence >= CONFIDENCE_HIGH:
        return "high confidence"
    if confidence >= CONFIDENCE_MEDIUM:
        return "medium confidence"
    if confidence > 0:
        return "low confidence"
    return "no reported confidence"


def _evidence_phrase(signal: ThreatIntelSignals) -> str:
    """Deterministic evidence sentence; never invents evidence."""
    if signal.evidence:
        return f"The provider returned evidence: {'; '.join(signal.evidence)}."
    return "The provider returned no specific evidence strings."


def _provider_finding(signal: ThreatIntelSignals, penalty: int) -> Finding:
    """Build the observable Finding for one provider signal.

    Every finding carries a deterministic ``explanation`` that answers WHAT
    the provider reported, WHO reported it, WHAT evidence was returned, HOW
    confident the signal is, and WHY it did (or did not) affect the risk
    assessment. Explanations are generated from the normalized signal only —
    never from raw vendor payloads, never from an AI service.
    """
    verdict_bits = []
    if signal.malicious:
        verdict_bits.append("malicious")
    if signal.suspicious:
        verdict_bits.append("suspicious")

    if signal.status != "available":
        reason_hint = f" reason '{signal.reason}'" if signal.reason else ""
        return Finding(
            title="External threat intelligence unavailable",
            severity="info",
            description=(
                f"{signal.provider} could not produce a threat verdict"
                f"{reason_hint}."
            ),
            explanation=(
                f"{signal.provider} could not be reached or did not return a "
                f"usable result{reason_hint}. No threat determination was made "
                f"from this provider, and this failure did not change the "
                f"domain's risk assessment."
            ),
            evidence="; ".join(signal.evidence),
            confidence=signal.confidence,
        )

    if not verdict_bits:
        return Finding(
            title="External threat intelligence clean result",
            severity="info",
            description=(
                f"{signal.provider} returned no threat verdict for the target "
                f"({_confidence_phrase(signal.confidence)}, {signal.confidence}/100)."
            ),
            explanation=(
                f"{signal.provider} returned no threat match for the submitted "
                f"URL, so this signal did not add malicious-risk evidence. "
                f"Note: this does not prove the domain is globally safe; every "
                f"other signal is evaluated independently."
            ),
            evidence="; ".join(signal.evidence),
            confidence=signal.confidence,
        )

    category_label = ", ".join(signal.categories) or "a known threat category"
    verdict_label = " and ".join(verdict_bits)
    severity = _severity_for(signal)
    title = (
        "External threat intelligence flag"
        if signal.malicious
        else "External threat intelligence suspicion"
    )
    impact = (
        f"This verdict contributed {penalty} point(s) to the domain's risk "
        f"assessment."
        if penalty
        else "This verdict carried no confidence, so it did not change the risk assessment."
    )

    return Finding(
        title=title,
        severity=severity,
        description=(
            f"{signal.provider} reported the target as {verdict_label} "
            f"({category_label})."
        ),
        explanation=(
            f"{signal.provider} reported the submitted URL as {verdict_label} in the "
            f"{category_label} category with {_confidence_phrase(signal.confidence)} "
            f"({signal.confidence}/100). {_evidence_phrase(signal)} "
            f"This evidence increased the domain's risk assessment. {impact}"
        ),
        recommendation="Verify the domain against the provider's console before trusting it.",
        evidence="; ".join(signal.evidence),
        confidence=signal.confidence,
    )


def _correlation_severity(correlated: CorrelationResult) -> str:
    """Severity for the aggregate verdict: confidence ladder mirrors
    ``_severity_for`` so a contested (conflict-discounted) threat never
    reads with more certainty than the evidence supports."""
    if correlated.consensus in {"malicious", "conflict"}:
        confidence = correlated.malicious_confidence
        if confidence >= CONFIDENCE_HIGH:
            return "critical"
        if confidence >= CONFIDENCE_MEDIUM:
            return "high"
        return "medium"
    if correlated.consensus == "suspicious":
        return "medium" if correlated.suspicious_confidence >= CONFIDENCE_HIGH else "low"
    return "info"


def _correlation_finding(correlated: CorrelationResult, penalty: int) -> Finding:
    """One aggregate finding SUPPLEMENTING the per-provider findings.

    It answers WHAT CyberShield concludes from ALL providers and WHY (the
    counts, agreement/conflict state, and consolidated confidence), while
    the per-provider findings keep the original evidence and provenance.
    Provider-independent: generated only from the normalized
    ``CorrelationResult``. The caller only invokes it when at least one
    provider answered (``available_count > 0``).
    """
    available = correlated.available_count
    pieces: list[str] = []
    if correlated.malicious_count:
        pieces.append(
            f"{correlated.malicious_count} of {available} available provider(s) "
            f"reported the target as malicious"
        )
    if correlated.suspicious_count:
        pieces.append(
            f"{correlated.suspicious_count} of {available} available provider(s) "
            f"reported suspicious activity"
        )
    if correlated.clean_count:
        pieces.append(
            f"{correlated.clean_count} of {available} available provider(s) "
            f"reported no threat match"
        )
    if correlated.unavailable_count:
        pieces.append(f"{correlated.unavailable_count} provider(s) were unavailable")

    if correlated.consensus == "conflict":
        severity = _correlation_severity(correlated)
        confidence = correlated.malicious_confidence
        agreement = (
            f"Providers materially disagreed: {correlated.malicious_count} flagged "
            f"the target as malicious while {correlated.clean_count} reported "
            f"no threat match. The conflict is preserved and the assessment "
            f"is rated with {_confidence_phrase(confidence)} "
            f"({confidence}/100)."
        )
    elif correlated.consensus in {"malicious", "suspicious"}:
        severity = _correlation_severity(correlated)
        confidence = (
            correlated.malicious_confidence
            if correlated.consensus == "malicious"
            else correlated.suspicious_confidence
        )
        if correlated.agreement == "consistent" and correlated.malicious_count >= 2:
            agreement = (
                "The providers showed strong agreement, which added "
                f"{THREAT_INTEL_AGREEMENT_BONUS} point(s) of "
                "corroboration to the assessment."
            )
        else:
            agreement = (
                f"The available providers {correlated.agreement}, so the "
                "assessment is rated only at the confidence each provider "
                "actually supplied."
            )
    else:  # consensus == "clean"
        severity = "info"
        confidence = 0
        agreement = (
            "No available provider flagged the target, so no threat evidence "
            "was added from external sources."
        )

    impact = (
        f"The evidence contributed {penalty} point(s) to the domain's risk "
        "assessment."
        if penalty
        else "The evidence did not change the domain's risk assessment."
    )
    title = (
        "Correlated threat intelligence: conflicting verdicts"
        if correlated.consensus == "conflict"
        else (
            "Correlated threat intelligence verdict"
            if correlated.consensus in {"malicious", "suspicious"}
            else "Correlated threat intelligence: no threat reported"
        )
    )

    category_label = ", ".join(correlated.categories) or "known threat categories"
    return Finding(
        title=title,
        severity=severity,
        description="Correlated assessment from " + "; ".join(pieces) + ".",
        explanation=(
            f"This finding aggregates all provider evidence. "
            f"{'; '.join(pieces)}. {agreement} Categories observed: "
            f"{category_label}."
        ),
        recommendation=(
            "Reconcile the conflicting provider verdicts manually before "
            "acting on this domain."
            if correlated.consensus == "conflict"
            else "Verify the verdicts in each provider's console before acting."
        ),
        evidence="; ".join(correlated.evidence),
        confidence=confidence,
    )
