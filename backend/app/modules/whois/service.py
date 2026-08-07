"""WHOIS module interface used by the ScanManager.

Composes the retrieval -> normalization -> intelligence pipeline and emits a
canonical :class:`ModuleResult`. No other module calls this one directly;
the ScanManager (via its registry) is the only orchestrator.
"""

import logging

from app.modules.whois.intelligence import evaluate_profile
from app.modules.whois.parser import parse_whois
from app.modules.whois.rules import (
    LOW_CONFIDENCE,
    LOOKUP_UNAVAILABLE_RULE,
    MODULE_NAME,
)
from app.modules.whois.scanner import WhoisUnavailableError, fetch_whois
from app.schemas.finding import Finding
from app.schemas.module_result import ModuleResult, score_to_status

logger = logging.getLogger("cybershield.whois")


def scan_whois_module(domain: str) -> ModuleResult:
    """Run the full WHOIS intelligence pipeline for a domain.

    A failed registry lookup yields an ``error`` result carrying the
    "WHOIS Lookup Unavailable" finding; it never raises.
    """
    hostname = domain.replace("https://", "").replace("http://", "").split("/")[0].split(":")[0].strip()

    try:
        raw = fetch_whois(hostname)
    except WhoisUnavailableError as exc:
        logger.warning("WHOIS lookup unavailable for %s: %s", hostname, exc)
        return ModuleResult(
            module=MODULE_NAME,
            status="error",
            score=100 - LOOKUP_UNAVAILABLE_RULE.penalty,
            confidence=LOW_CONFIDENCE,
            findings=[
                Finding(
                    title=LOOKUP_UNAVAILABLE_RULE.title,
                    severity=LOOKUP_UNAVAILABLE_RULE.severity,
                    description=f"WHOIS data is unavailable for {hostname}: {exc}",
                    recommendation=LOOKUP_UNAVAILABLE_RULE.recommendation,
                )
            ],
            details={"domain": hostname, "error": str(exc)},
        )

    profile = parse_whois(raw, hostname)
    intelligence = evaluate_profile(profile)

    logger.info(
        "WHOIS scan for %s: score %s, confidence %s, %d findings",
        hostname,
        intelligence.score,
        intelligence.confidence,
        len(intelligence.findings),
    )

    return ModuleResult(
        module=MODULE_NAME,
        status=score_to_status(intelligence.score),
        score=intelligence.score,
        confidence=intelligence.confidence,
        findings=intelligence.findings,
        details=profile.model_dump(),
    )


def run_whois_check(domain: str) -> ModuleResult:
    """Pipeline entry point consumed by the WHOISScanner registry adapter."""
    return scan_whois_module(domain)