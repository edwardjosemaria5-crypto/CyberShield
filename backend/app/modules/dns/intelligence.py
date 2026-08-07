"""DNS intelligence: turn a normalized profile into findings and a score.

Each rule is a small, focused check that mutates a shared
:class:`DnsIntelligenceResult`. Every finding carries the four educational
sections: description (what), explanation (why it matters), evidence
(concrete data), and recommendation (what to do). The module score is
computed here; the overall trust score and verdict belong to the risk engine.
"""

import logging
from dataclasses import dataclass, field

from app.modules.dns.models import DnsProfile
from app.modules.dns.rules import (
    DEFAULT_CONFIDENCE,
    DnsRule,
    DNSSEC_DISABLED_RULE,
    DOMAIN_NOT_RESOLVING_RULE,
    DUPLICATE_NAMESERVERS_RULE,
    EXCESSIVE_NAMESERVERS_RULE,
    INCONSISTENT_RESOLUTION_RULE,
    LOW_TTL_RULE,
    LOW_TTL_THRESHOLD,
    MAX_NAMESERVERS,
    MISSING_CAA_RULE,
    MISSING_DMARC_RULE,
    MISSING_MX_RULE,
    MISSING_SPF_RULE,
    SINGLE_NAMESERVER_RULE,
    SUSPICIOUS_CAA_RULE,
    DKIM_NOT_DETECTED_RULE,
)
from app.schemas.finding import Finding

logger = logging.getLogger("cybershield.dns")


@dataclass
class DnsIntelligenceResult:
    """Module-level outcome: score plus the findings that justify it."""

    score: int = 100
    confidence: int = DEFAULT_CONFIDENCE
    findings: list[Finding] = field(default_factory=list)


def evaluate_profile(profile: DnsProfile) -> DnsIntelligenceResult:
    """Apply every DNS intelligence rule to a normalized profile."""
    result = DnsIntelligenceResult()

    _check_resolution(profile, result)
    _check_email_security(profile, result)
    _check_network_security(profile, result)
    _check_infrastructure(profile, result)

    result.score = max(0, min(100, result.score))
    logger.debug(
        "DNS intelligence for %s: score %s (%d findings)",
        profile.domain,
        result.score,
        len(result.findings),
    )
    return result


def _check_resolution(profile: DnsProfile, result: DnsIntelligenceResult) -> None:
    if profile.ip_address is None and not profile.ipv6_addresses:
        _apply_rule(
            result,
            DOMAIN_NOT_RESOLVING_RULE,
            f"Domain {profile.domain} has no A or AAAA records.",
        )
        return

    if profile.caa_count == 0:
        _apply_rule(
            result,
            MISSING_CAA_RULE,
            f"Domain {profile.domain} publishes no CAA records.",
        )


def _check_email_security(profile: DnsProfile, result: DnsIntelligenceResult) -> None:
    if not profile.spf:
        _apply_rule(
            result,
            MISSING_SPF_RULE,
            f"Domain {profile.domain} publishes no SPF policy.",
        )
    if not profile.dmarc:
        _apply_rule(
            result,
            MISSING_DMARC_RULE,
            f"Domain {profile.domain} publishes no DMARC policy.",
        )
    if profile.mx_count == 0:
        _apply_rule(
            result,
            MISSING_MX_RULE,
            f"Domain {profile.domain} has no MX records.",
        )
    if profile.mx_count > 0 and not profile.dkim:
        _apply_rule(
            result,
            DKIM_NOT_DETECTED_RULE,
            f"Domain {profile.domain} accepts mail but publishes no DKIM key.",
        )


def _check_network_security(profile: DnsProfile, result: DnsIntelligenceResult) -> None:
    if profile.caa_count > 0 and not _has_issue_caa(profile.caa_records):
        _apply_rule(
            result,
            SUSPICIOUS_CAA_RULE,
            f"Domain {profile.domain} has CAA records but none authorize an issuer.",
        )
    if not profile.dnssec:
        _apply_rule(
            result,
            DNSSEC_DISABLED_RULE,
            f"Domain {profile.domain} publishes no DNSKEY records.",
        )


def _check_infrastructure(profile: DnsProfile, result: DnsIntelligenceResult) -> None:
    if profile.ns_count > MAX_NAMESERVERS:
        _apply_rule(
            result,
            EXCESSIVE_NAMESERVERS_RULE,
            f"Domain {profile.domain} delegates to {profile.ns_count} name servers.",
        )
    elif profile.ns_count == 1:
        _apply_rule(
            result,
            SINGLE_NAMESERVER_RULE,
            f"Domain {profile.domain} delegates to a single name server.",
        )
    if profile.nameserver_duplicates:
        _apply_rule(
            result,
            DUPLICATE_NAMESERVERS_RULE,
            f"Domain {profile.domain} lists duplicate name servers.",
        )
    if profile.ttl_min is not None and profile.ttl_min < LOW_TTL_THRESHOLD:
        _apply_rule(
            result,
            LOW_TTL_RULE,
            f"Domain {profile.domain} uses a minimum TTL of {profile.ttl_min}s.",
        )
    if profile.resolution_consistent is False:
        _apply_rule(
            result,
            INCONSISTENT_RESOLUTION_RULE,
            f"Public resolvers disagree on the addresses for {profile.domain}.",
        )


def _has_issue_caa(caa_records: list[str]) -> bool:
    """True when any CAA record carries an 'issue' tag."""
    return any("issue" in record for record in caa_records)


def _apply_rule(result: DnsIntelligenceResult, rule: DnsRule, description: str, evidence: str = "") -> None:
    result.score -= rule.penalty
    result.findings.append(
        Finding(
            title=rule.title,
            severity=rule.severity,
            description=description,
            explanation=rule.explanation,
            recommendation=rule.recommendation,
            evidence=evidence,
            confidence=result.confidence,
        )
    )
