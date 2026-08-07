"""DNS module interface used by the ScanManager.

Composes the retrieval -> normalization -> intelligence pipeline and emits a
canonical :class:`ModuleResult`. No other module calls this one directly;
the ScanManager (via its registry) is the only orchestrator.
"""

import logging
from collections.abc import Callable

from app.modules.dns import scanner as dns_scanner
from app.modules.dns.intelligence import evaluate_profile
from app.modules.dns.models import DnsProfile
from app.modules.dns.parser import parse_dns_records
from app.modules.dns.rules import MODULE_NAME
from app.schemas.module_result import ModuleResult, score_to_status

logger = logging.getLogger("cybershield.dns")


def scan_dns_module(
    domain: str,
    resolver: Callable[[str], dict] | None = None,
) -> ModuleResult:
    """Run the full DNS intelligence pipeline for a hostname.

    ``resolver`` is injectable for tests; it must return the raw records
    dict produced by :func:`app.modules.dns.resolver.resolve_domain`.
    Defaults to the live resolver, looked up at call time so tests can
    monkeypatch :attr:`app.modules.dns.scanner.resolve_domain`.
    """
    hostname = domain.replace("https://", "").replace("http://", "").split("/")[0].split(":")[0].strip()

    fetch = resolver if resolver is not None else dns_scanner.resolve_domain
    records = fetch(hostname)
    profile = parse_dns_records(hostname, records)
    intelligence = evaluate_profile(profile)

    logger.info(
        "DNS scan for %s: score %s, confidence %s, %d findings",
        hostname,
        intelligence.score,
        intelligence.confidence,
        len(intelligence.findings),
    )

    details = profile.model_dump()
    details["records"] = records

    return ModuleResult(
        module=MODULE_NAME,
        status=score_to_status(intelligence.score),
        score=intelligence.score,
        confidence=intelligence.confidence,
        findings=intelligence.findings,
        details=details,
    )


def run_dns_check(domain: str) -> ModuleResult:
    """Pipeline entry point consumed by the DNSScanner registry adapter."""
    return scan_dns_module(domain)
