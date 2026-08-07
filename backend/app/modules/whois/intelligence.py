"""WHOIS intelligence: turn a normalized profile into findings and a score.

Each rule is a small, focused check that mutates a shared
:class:`WhoisIntelligenceResult`. The module score is computed here from the
configured penalties; the overall trust score and verdict remain the
responsibility of the risk engine.
"""

import logging
from dataclasses import dataclass, field

from app.modules.whois.models import WhoisProfile
from app.modules.whois.rules import (
    DEFAULT_CONFIDENCE,
    DNSSEC_DISABLED_MARKERS,
    DOMAIN_EXPIRED_RULE,
    DOMAIN_EXPIRING_RULE,
    DNSSEC_DISABLED_RULE,
    EXPIRY_RISK_DAYS,
    MISSING_NAMESERVERS_RULE,
    MISSING_REGISTRAR_RULE,
    RECENT_REGISTRATION_DAYS,
    RECENT_REGISTRATION_RULE,
    Rule,
)
from app.schemas.finding import Finding

logger = logging.getLogger("cybershield.whois")


@dataclass
class WhoisIntelligenceResult:
    """Module-level outcome: score plus the findings that justify it."""

    score: int = 100
    confidence: int = DEFAULT_CONFIDENCE
    findings: list[Finding] = field(default_factory=list)


def evaluate_profile(profile: WhoisProfile) -> WhoisIntelligenceResult:
    """Apply every WHOIS intelligence rule to a normalized profile."""
    result = WhoisIntelligenceResult(confidence=DEFAULT_CONFIDENCE)

    _check_recent_registration(profile, result)
    _check_expiration(profile, result)
    _check_registrar(profile, result)
    _check_nameservers(profile, result)
    _check_dnssec(profile, result)

    result.score = max(0, min(100, result.score))
    logger.debug(
        "WHOIS intelligence for %s: score %s (%d findings)",
        profile.domain,
        result.score,
        len(result.findings),
    )
    return result


def _check_recent_registration(profile: WhoisProfile, result: WhoisIntelligenceResult) -> None:
    if profile.domain_age_days is not None and profile.domain_age_days < RECENT_REGISTRATION_DAYS:
        _apply_rule(
            result,
            RECENT_REGISTRATION_RULE,
            f"The domain was registered only {profile.domain_age_days} days ago.",
        )


def _check_expiration(profile: WhoisProfile, result: WhoisIntelligenceResult) -> None:
    if profile.expires_in_days is None:
        return
    if profile.expires_in_days < 0:
        _apply_rule(result, DOMAIN_EXPIRED_RULE, "The domain registration has already expired.")
    elif profile.expires_in_days <= EXPIRY_RISK_DAYS:
        _apply_rule(
            result,
            DOMAIN_EXPIRING_RULE,
            f"The domain registration expires in {profile.expires_in_days} days.",
        )


def _check_registrar(profile: WhoisProfile, result: WhoisIntelligenceResult) -> None:
    if not profile.registrar:
        _apply_rule(result, MISSING_REGISTRAR_RULE, "No registrar information was returned.")

    if not profile.organization and not profile.country:
        logger.debug(
            "WHOIS record for %s is missing organization/country metadata",
            profile.domain,
        )


def _check_nameservers(profile: WhoisProfile, result: WhoisIntelligenceResult) -> None:
    if not profile.name_servers:
        _apply_rule(
            result,
            MISSING_NAMESERVERS_RULE,
            "WHOIS returned no name servers for the domain.",
        )


def _check_dnssec(profile: WhoisProfile, result: WhoisIntelligenceResult) -> None:
    if profile.dnssec and profile.dnssec.strip().lower() in DNSSEC_DISABLED_MARKERS:
        _apply_rule(
            result,
            DNSSEC_DISABLED_RULE,
            f"DNSSEC status is '{profile.dnssec}'.",
        )


def _apply_rule(result: WhoisIntelligenceResult, rule: Rule, description: str) -> None:
    result.score -= rule.penalty
    result.findings.append(
        Finding(
            title=rule.title,
            severity=rule.severity,
            description=description,
            recommendation=rule.recommendation,
        )
    )