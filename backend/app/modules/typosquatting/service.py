"""Typosquatting module interface used by the ScanManager.

Composes retrieval -> normalization -> intelligence and emits a canonical
:class:`ModuleResult`. The brand database is injectable for tests.
"""

import logging
from collections.abc import Callable

from app.modules.brand_detection.brands import get_brand_database
from app.modules.typosquatting.intelligence import evaluate_profile
from app.modules.typosquatting.parser import build_profile, extract_sld
from app.modules.typosquatting.rules import MODULE_NAME
from app.modules.typosquatting.scanner import find_brand_matches
from app.schemas.module_result import ModuleResult, score_to_status

logger = logging.getLogger("cybershield.typosquatting")


def scan_typosquatting_module(
    domain: str,
    matcher: Callable[[str, dict], list] = find_brand_matches,
    brand_database: dict | None = None,
) -> ModuleResult:
    """Run the full typosquatting pipeline for a hostname.

    ``matcher`` and ``brand_database`` are injectable for tests.
    """
    hostname = domain.replace("https://", "").replace("http://", "").split("/")[0].split(":")[0].strip()
    sld = extract_sld(hostname)
    brands = brand_database if brand_database is not None else get_brand_database()

    matches = matcher(sld, brands)
    matches = _filter_legitimate_domains(hostname, matches, brands)
    profile = build_profile(hostname, matches)
    intelligence = evaluate_profile(profile)

    logger.info(
        "Typosquatting scan for %s: score %s, %d matches",
        hostname,
        intelligence.score,
        len(profile.matches),
    )

    return ModuleResult(
        module=MODULE_NAME,
        status=score_to_status(intelligence.score),
        score=intelligence.score,
        confidence=intelligence.confidence,
        findings=intelligence.findings,
        details={
            "domain": hostname,
            "sld": profile.sld,
            "total_brands_compared": len(brands),
            "matches": [m.model_dump() for m in profile.matches],
            "best_match": profile.best_match.model_dump() if profile.best_match else None,
        },
    )


def run_typosquatting_check(domain: str) -> ModuleResult:
    """Pipeline entry point consumed by the TyposquattingScanner registry adapter."""
    return scan_typosquatting_module(domain)


def _filter_legitimate_domains(hostname: str, matches: list, brands: dict) -> list:
    """Drop matches whose brand is the domain itself (an official brand domain)."""
    hostname = hostname.rstrip(".").lower()
    kept = []
    for match in matches:
        name = match.brand.lower()
        entry = brands.get(name)
        if entry and _is_official_domain(hostname, entry):
            continue
        kept.append(match)
    return kept


def _is_official_domain(hostname: str, entry: dict) -> bool:
    for domain in entry.get("domains", []):
        domain = domain.lower().rstrip(".")
        if hostname == domain or hostname.endswith("." + domain):
            return True
    return False
