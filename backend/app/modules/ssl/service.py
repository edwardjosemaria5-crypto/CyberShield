"""SSL/TLS module interface used by the ScanManager.

Composes the retrieval -> normalization -> intelligence pipeline and emits a
canonical :class:`ModuleResult`. No other module calls this one directly;
the ScanManager (via its registry) is the only orchestrator.
"""

import logging
from collections.abc import Callable

from app.modules.ssl.intelligence import evaluate_profile
from app.modules.ssl.models import TlsHandshake
from app.modules.ssl.parser import parse_handshake
from app.modules.ssl.rules import MODULE_NAME
from app.modules.ssl.scanner import BlockedTargetError, TlsUnavailableError, fetch_tls
from app.schemas.finding import Finding
from app.schemas.module_result import ModuleResult, score_to_status
from app.utils.networking import parse_host

logger = logging.getLogger("cybershield.ssl")


def scan_ssl_module(
    domain: str,
    fetcher: Callable[[str], TlsHandshake] = fetch_tls,
) -> ModuleResult:
    """Run the full SSL/TLS intelligence pipeline for a hostname.

    ``fetcher`` is injectable for tests; it must return a
    :class:`TlsHandshake` or raise :class:`TlsUnavailableError`.
    """
    hostname = parse_host(domain)

    try:
        handshake = fetcher(hostname)
    except TlsUnavailableError:
        logger.info("No TLS service detected for %s", hostname)
        handshake = None
    except BlockedTargetError as exc:
        return ModuleResult(
            module=MODULE_NAME,
            status="error",
            score=50,
            confidence=90,
            findings=[
                Finding(
                    title="SSL scan refused",
                    severity="low",
                    description=str(exc),
                    recommendation="Scan a public hostname only.",
                )
            ],
            details={"host": hostname, "error": str(exc)},
        )

    profile = parse_handshake(handshake)
    intelligence = evaluate_profile(profile)

    logger.info(
        "SSL scan for %s: score %s, confidence %s, %d findings",
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


def run_ssl_check(domain: str) -> ModuleResult:
    """Pipeline entry point consumed by the SSLScanner registry adapter."""
    return scan_ssl_module(domain)