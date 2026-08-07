"""SSL/TLS intelligence: turn a normalized profile into findings and a score.

Each rule is a small, focused check that mutates a shared
:class:`SslIntelligenceResult`. Every finding carries the four educational
sections: description (what), explanation (why it matters), evidence
(concrete data), and recommendation (what to do). The module score is
computed here; the overall trust score and verdict belong to the risk engine.
"""

import logging
from dataclasses import dataclass, field

from app.modules.ssl.models import SslProfile
from app.modules.ssl.rules import (
    DEFAULT_CONFIDENCE,
    EXPIRING_CERT_RULE,
    EXPIRED_CERT_RULE,
    HOSTNAME_MISMATCH_RULE,
    MISSING_HTTPS_RULE,
    NO_FORWARD_SECRECY_RULE,
    OLD_TLS_RULE,
    REDUCED_CONFIDENCE,
    SELF_SIGNED_RULE,
    SslRule,
    UNTRUSTED_CHAIN_RULE,
    WEAK_CIPHER_RULE,
    WEAK_KEY_RULE,
    WEAK_SIGNATURE_RULE,
    WEAK_TLS_VERSIONS,
)
from app.schemas.finding import Finding

logger = logging.getLogger("cybershield.ssl")


@dataclass
class SslIntelligenceResult:
    """Module-level outcome: score plus the findings that justify it."""

    score: int = 100
    confidence: int = DEFAULT_CONFIDENCE
    findings: list[Finding] = field(default_factory=list)


def evaluate_profile(profile: SslProfile) -> SslIntelligenceResult:
    """Apply every SSL/TLS intelligence rule to a normalized profile."""
    if profile.certificate_chain_valid is False:
        confidence = REDUCED_CONFIDENCE
    else:
        confidence = DEFAULT_CONFIDENCE
    result = SslIntelligenceResult(confidence=confidence)

    if not profile.https_available:
        _apply_rule(result, MISSING_HTTPS_RULE, f"Host {profile.domain} does not serve TLS on port 443.")
        result.score = 0
        logger.info("SSL intelligence for %s: no HTTPS service", profile.domain)
        return result

    _check_validity(profile, result)
    _check_trust(profile, result)
    _check_tls_version(profile, result)
    _check_cipher(profile, result)
    _check_signature(profile, result)
    _check_key(profile, result)
    _check_identity(profile, result)

    result.score = max(0, min(100, result.score))
    logger.info(
        "SSL intelligence for %s: score %s, confidence %s (%d findings)",
        profile.domain,
        result.score,
        result.confidence,
        len(result.findings),
    )
    return result


def _check_validity(profile: SslProfile, result: SslIntelligenceResult) -> None:
    if profile.expired:
        _apply_rule(
            result,
            EXPIRED_CERT_RULE,
            f"The certificate for {profile.domain} expired "
            f"{abs(profile.expires_in_days or 0)} days ago.",
            evidence=f"valid_until={profile.valid_until}",
        )
    elif profile.expiring:
        _apply_rule(
            result,
            EXPIRING_CERT_RULE,
            f"The certificate for {profile.domain} expires in {profile.expires_in_days} days.",
            evidence=f"valid_until={profile.valid_until}",
        )


def _check_trust(profile: SslProfile, result: SslIntelligenceResult) -> None:
    if profile.self_signed:
        _apply_rule(
            result,
            SELF_SIGNED_RULE,
            f"The certificate for {profile.domain} is signed by itself "
            f"(issuer == subject: {profile.issuer_common_name or 'unknown'}).",
        )
    elif profile.certificate_chain_valid is False:
        _apply_rule(
            result,
            UNTRUSTED_CHAIN_RULE,
            f"The certificate chain for {profile.domain} was rejected by the "
            "system trust store.",
        )


def _check_tls_version(profile: SslProfile, result: SslIntelligenceResult) -> None:
    if profile.tls_version and profile.tls_version in WEAK_TLS_VERSIONS:
        _apply_rule(
            result,
            OLD_TLS_RULE,
            f"The server negotiates {profile.tls_version}.",
            evidence=f"tls_version={profile.tls_version}",
        )


def _check_cipher(profile: SslProfile, result: SslIntelligenceResult) -> None:
    if profile.weak_cipher:
        _apply_rule(
            result,
            WEAK_CIPHER_RULE,
            f"The server negotiated a deprecated cipher suite: {profile.cipher_suite}.",
            evidence=f"cipher_suite={profile.cipher_suite}",
        )
    elif profile.forward_secrecy is False:
        _apply_rule(
            result,
            NO_FORWARD_SECRECY_RULE,
            f"The negotiated key exchange ({profile.cipher_suite}) does not "
            "provide forward secrecy.",
            evidence=f"cipher_suite={profile.cipher_suite}",
        )


def _check_signature(profile: SslProfile, result: SslIntelligenceResult) -> None:
    if profile.weak_signature:
        _apply_rule(
            result,
            WEAK_SIGNATURE_RULE,
            f"The certificate is signed with a deprecated hash: {profile.signature_algorithm}.",
            evidence=f"signature_algorithm={profile.signature_algorithm}",
        )


def _check_key(profile: SslProfile, result: SslIntelligenceResult) -> None:
    if profile.weak_key:
        _apply_rule(
            result,
            WEAK_KEY_RULE,
            f"The certificate key is only {profile.key_size} bits "
            f"({profile.public_key_algorithm}).",
            evidence=f"key_size={profile.key_size} public_key_algorithm={profile.public_key_algorithm}",
        )


def _check_identity(profile: SslProfile, result: SslIntelligenceResult) -> None:
    if profile.hostname_matches is False:
        _apply_rule(
            result,
            HOSTNAME_MISMATCH_RULE,
            f"The certificate does not cover {profile.domain}.",
            evidence=f"san_entries={profile.san_entries}",
        )


def _apply_rule(result: SslIntelligenceResult, rule: SslRule, description: str, evidence: str = "") -> None:
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