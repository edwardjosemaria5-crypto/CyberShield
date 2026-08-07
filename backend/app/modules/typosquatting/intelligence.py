"""Typosquatting intelligence: turn a profile into findings and a score.

Scoring model: a brand match with high similarity or a deliberate attack
technique (homograph / substitution / keyboard adjacent) is a strong
impersonation signal. Findings explain what was detected, why it matters,
and how attackers use the technique.
"""

import logging
from dataclasses import dataclass, field

from app.modules.typosquatting.models import TyposquattingProfile
from app.modules.typosquatting.rules import (
    DEFAULT_CONFIDENCE,
    DELIBERATE_TECHNIQUES,
    HOMOGRAPH_PENALTY,
    PENALTY_CRITICAL,
    PENALTY_HIGH,
    PENALTY_LOW,
    SIMILARITY_CRITICAL,
    SIMILARITY_HIGH,
    SIMILARITY_LOW,
    TECHNIQUE_LABELS,
)
from app.schemas.finding import Finding

logger = logging.getLogger("cybershield.typosquatting")

#: Educational text describing each impersonation technique.
TECHNIQUE_EXPLANATIONS = {
    "homograph": (
        "The domain substitutes characters from another Unicode script (e.g. Cyrillic "
        "or Greek) that look identical to Latin letters. This is a Unicode homograph "
        "attack: the address bar shows a domain that appears to be the legitimate "
        "brand but is actually registered by the attacker."
    ),
    "substitution": (
        "Digits and symbols visually replace letters (0 for o, 1 for l, 4 for a, "
        "@ for a). These 'leetspeak' substitutions are a classic typosquatting "
        "technique used to register domains that pass casual inspection."
    ),
    "keyboard": (
        "A letter was replaced with a key that sits adjacent to it on the keyboard. "
        "This simulates a natural typing mistake so victims believe they simply "
        "typed the brand incorrectly, while the attacker's domain captures the traffic."
    ),
    "transposition": (
        "Two adjacent letters were swapped. Transposition imitates a common typing "
        "error and is often used to register look-alike brand domains."
    ),
    "repeated": (
        "A character of the brand name was doubled (e.g. gooogle.com). The domain "
        "reads identically to the legitimate brand to most users."
    ),
    "missing": (
        "A character of the brand name was dropped. Missing a single letter is one "
        "of the most common typosquatting patterns because users rarely notice it."
    ),
    "extra": (
        "An extra character was added to the brand name. Slightly longer look-alike "
        "domains are frequently registered by attackers to catch mistyped URLs."
    ),
    "similar": (
        "The domain is lexically close to a known brand. Similarity alone is weak "
        "evidence, but combined with other indicators it supports an impersonation "
        "assessment."
    ),
}


@dataclass
class TyposquattingIntelligenceResult:
    """Module-level outcome: score plus the findings that justify it."""

    score: int = 100
    confidence: int = DEFAULT_CONFIDENCE
    findings: list[Finding] = field(default_factory=list)


def evaluate_profile(profile: TyposquattingProfile) -> TyposquattingIntelligenceResult:
    """Apply typosquatting rules to a normalized profile."""
    result = TyposquattingIntelligenceResult(confidence=DEFAULT_CONFIDENCE)

    best = profile.best_match
    if best is None:
        logger.debug("Typosquatting for %s: no brand match", profile.domain)
        return result

    severity, penalty = _classify_similarity(best.similarity)
    _apply_match_finding(result, profile.domain, best, severity, penalty)

    if best.technique == "homograph":
        _apply_technique_finding(
            result,
            "Unicode Homograph Attack",
            "high",
            HOMOGRAPH_PENALTY,
            f"Domain {profile.domain} is not spelled with plain Latin characters.",
            TECHNIQUE_EXPLANATIONS["homograph"],
        )

    result.score = max(0, min(100, result.score))
    logger.debug(
        "Typosquatting for %s: score %s, best match %s (sim %s, %s)",
        profile.domain,
        result.score,
        best.brand,
        best.similarity,
        best.technique,
    )
    return result


def _classify_similarity(similarity: int) -> tuple[str, int]:
    if similarity >= SIMILARITY_CRITICAL:
        return "critical", PENALTY_CRITICAL
    if similarity >= SIMILARITY_HIGH:
        return "high", PENALTY_HIGH
    return "medium", PENALTY_LOW


def _apply_match_finding(
    result: TyposquattingIntelligenceResult,
    domain: str,
    match,
    severity: str,
    penalty: int,
) -> None:
    result.score -= penalty
    result.findings.append(
        Finding(
            title=f"Domain Resembles {match.brand}",
            severity=severity,
            description=(
                f"Domain '{domain}' resembles the brand "
                f"{match.brand} with {match.similarity}% similarity."
            ),
            explanation=TECHNIQUE_EXPLANATIONS.get(
                match.technique, TECHNIQUE_EXPLANATIONS["similar"]
            ),
            recommendation=(
                "Do not trust this domain as the legitimate brand. Verify the "
                "exact URL in the address bar and access the brand only through "
                "its official website."
            ),
            evidence=f"candidate={domain}, brand={match.brand}, technique={TECHNIQUE_LABELS.get(match.technique, match.technique)}, similarity={match.similarity}",
            confidence=result.confidence,
        )
    )


def _apply_technique_finding(
    result: TyposquattingIntelligenceResult,
    title: str,
    severity: str,
    penalty: int,
    description: str,
    explanation: str,
) -> None:
    result.score -= penalty
    result.findings.append(
        Finding(
            title=title,
            severity=severity,
            description=description,
            explanation=explanation,
            recommendation=(
                "Treat this domain as a potential phishing target. Contact the "
                "brand through its official channels before entering any credentials."
            ),
            confidence=result.confidence,
        )
    )
