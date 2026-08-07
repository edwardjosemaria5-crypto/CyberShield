"""Brand detection module interface used by the ScanManager.

Composes retrieval -> normalization -> intelligence and emits a canonical
:class:`ModuleResult`.
"""

import logging
from collections.abc import Callable

from app.modules.brand_detection.intelligence import evaluate_profile
from app.modules.brand_detection.parser import parse_brand_profile
from app.modules.brand_detection.rules import MODULE_NAME
from app.modules.brand_detection.scanner import scan_brand_detection
from app.schemas.module_result import ModuleResult, score_to_status

logger = logging.getLogger("cybershield.brand_detection")


def scan_brand_detection_module(
    domain: str,
    fetcher: Callable[[str], dict] | None = None,
) -> ModuleResult:
    """Run the full brand-detection pipeline for a hostname.

    ``fetcher`` is injectable for tests; it must return the raw dict produced
    by :func:`app.modules.brand_detection.scanner.scan_brand_detection`.
    """
    hostname = domain.replace("https://", "").replace("http://", "").split("/")[0].split(":")[0].strip()

    fetch = fetcher if fetcher is not None else scan_brand_detection
    raw = fetch(hostname)
    profile = parse_brand_profile(raw)
    intelligence = evaluate_profile(profile)

    logger.info(
        "Brand detection scan for %s: score %s, %d findings",
        hostname,
        intelligence.score,
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


def run_brand_detection_check(domain: str) -> ModuleResult:
    """Pipeline entry point consumed by the BrandDetectionScanner registry adapter."""
    return scan_brand_detection_module(domain)
