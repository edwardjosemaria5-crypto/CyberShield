"""Brand detection intelligence: turn a profile into findings and a score.

A brand-plus-suspicious-term combination (e.g. "paypal-login-security") is
treated as a strong impersonation signal even when lexical similarity is
low, because attackers stack descriptive keywords onto a brand name. Pure
similarity (from the typosquatting matcher) is a secondary, weaker signal.
"""

import logging
from dataclasses import dataclass, field

from app.modules.brand_detection.models import BrandDetectionProfile
from app.modules.brand_detection.rules import (
    DEFAULT_CONFIDENCE,
    PENALTY_BRAND_AND_TERM,
    PENALTY_BRAND_ONLY,
    PENALTY_HYPENATED,
    PENALTY_MULTIPLE_TERMS,
    PENALTY_TERM_ONLY,
    SEVERITY_BRAND_AND_TERM,
    SEVERITY_BRAND_ONLY,
)
from app.schemas.finding import Finding

logger = logging.getLogger("cybershield.brand_detection")


@dataclass
class BrandDetectionIntelligenceResult:
    """Module-level outcome: score plus the findings that justify it."""

    score: int = 100
    confidence: int = DEFAULT_CONFIDENCE
    findings: list[Finding] = field(default_factory=list)


def evaluate_profile(profile: BrandDetectionProfile) -> BrandDetectionIntelligenceResult:
    """Apply brand-detection rules to a normalized profile."""
    result = BrandDetectionIntelligenceResult(confidence=DEFAULT_CONFIDENCE)

    strong_signals = [s for s in profile.signals if s.suspicious_terms]
    brand_only_signals = [s for s in profile.signals if not s.suspicious_terms]

    if strong_signals:
        signal = strong_signals[0]
        result.score -= PENALTY_BRAND_AND_TERM
        if len(profile.suspicious_terms) > 1:
            result.score -= PENALTY_MULTIPLE_TERMS
        result.findings.append(
            _impersonation_finding(
                result,
                profile.domain,
                signal,
                SEVERITY_BRAND_AND_TERM,
                explanation=(
                    "The domain combines the brand name with login/banking-related "
                    "keywords such as "
                    f"'{', '.join(signal.suspicious_terms)}'. Attackers register such "
                    "combo domains so phishing links appear plausible while capturing "
                    "credentials and sensitive data. HTTPS on such a page only "
                    "encrypts the traffic; it does not prove the site is the real brand."
                ),
                recommendation=(
                    "Do not enter credentials. Navigate to the brand's official site "
                    "directly and report the domain to the brand's security team."
                ),
            )
        )
    elif brand_only_signals:
        signal = brand_only_signals[0]
        result.score -= PENALTY_BRAND_ONLY
        result.findings.append(
            _impersonation_finding(
                result,
                profile.domain,
                signal,
                SEVERITY_BRAND_ONLY,
                explanation=(
                    f"Domain '{profile.domain}' embeds '{signal.matched_alias}', a "
                    "well-known brand name, outside the brand's registered domain. "
                    "Such look-like domains are frequently registered for "
                    "impersonation and social engineering."
                ),
                recommendation=(
                    "Verify the exact domain before trusting it. Legitimate brands "
                    "only use their own registered domains (e.g. paypal.com)."
                ),
            )
        )
    elif profile.suspicious_terms:
        result.score -= PENALTY_TERM_ONLY
        result.findings.append(
            Finding(
                title="Suspicious Keywords in Domain",
                severity="low",
                description=(
                    f"Domain '{profile.domain}' contains suspicious keywords: "
                    f"{', '.join(profile.suspicious_terms)}."
                ),
                explanation=(
                    "Login, banking, wallet, and support keywords are common in "
                    "phishing and credential-harvesting domains. Without a brand "
                    "match this is a weak signal, but it lowers trust."
                ),
                recommendation=(
                    "Treat the domain with caution and verify its legitimacy before "
                    "sharing personal data."
                ),
                confidence=result.confidence,
            )
        )

    if profile.hyphens >= 2:
        result.score -= PENALTY_HYPENATED
        result.findings.append(
            Finding(
                title="Excessive Hyphenation",
                severity="info",
                description=(
                    f"Domain '{profile.domain}' contains {profile.hyphens} hyphens."
                ),
                explanation=(
                    "Multi-part hyphenated domains are a common typosquatting "
                    "layout: brand-name + keyword + top-level (e.g. "
                    "paypal-login-security.com)."
                ),
                recommendation="Note the hyphenation as a structural impersonation indicator.",
                confidence=result.confidence,
            )
        )

    result.score = max(0, min(100, result.score))
    logger.debug(
        "Brand detection for %s: score %s, %d findings",
        profile.domain,
        result.score,
        len(result.findings),
    )
    return result


def _impersonation_finding(
    result: BrandDetectionIntelligenceResult,
    domain: str,
    signal,
    severity: str,
    explanation: str,
    recommendation: str,
) -> Finding:
    return Finding(
        title=f"Potential Brand Impersonation: {signal.brand}",
        severity=severity,
        description=(
            f"Domain '{domain}' impersonates the brand "
            f"{signal.brand} (matched '{signal.matched_alias}' in label '{signal.context}')."
        ),
        explanation=explanation,
        recommendation=recommendation,
        evidence=(
            f"candidate={domain}, alias={signal.matched_alias}, "
            f"suspicious_terms={','.join(signal.suspicious_terms)}"
        ),
        confidence=result.confidence,
    )