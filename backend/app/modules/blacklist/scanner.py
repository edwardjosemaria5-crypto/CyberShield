import socket

from app.schemas.finding import Finding
from app.schemas.module_result import ModuleResult, score_to_status
from .rules import (
    BLACKLISTED_PENALTY,
    DEFAULT_CONFIDENCE,
    DNSBL_LISTS,
    KNOWN_MALICIOUS_DOMAINS,
    MODULE_NAME,
)


def _check_dnsbl(ip: str) -> list[str]:
    reversed_ip = ".".join(reversed(ip.split(".")))
    hits = []
    for dnsbl in DNSBL_LISTS:
        query = f"{reversed_ip}.{dnsbl}"
        try:
            socket.gethostbyname(query)
            hits.append(dnsbl)
        except Exception:
            pass
    return hits


def scan_blacklist_module(domain: str) -> ModuleResult:
    """Check the target against DNS blocklists and the static malicious feed."""
    hostname = domain.replace("https://", "").replace("http://", "").split("/")[0].split(":")[0].lower()

    flagged_lists: list[str] = []
    static_flagged = hostname in KNOWN_MALICIOUS_DOMAINS

    try:
        ip = socket.gethostbyname(hostname)
        flagged_lists = _check_dnsbl(ip)
    except Exception:
        flagged_lists = []

    is_blacklisted = static_flagged or bool(flagged_lists)
    score = 100 - (BLACKLISTED_PENALTY if is_blacklisted else 0)

    findings: list[Finding] = []
    if is_blacklisted:
        sources = flagged_lists or ["static malicious feed"]
        findings.append(
            Finding(
                title="Domain blacklisted",
                severity="critical",
                description=f"Domain flagged on: {', '.join(sources)}.",
                recommendation="Do not interact with the domain; verify reputation before use.",
            )
        )

    return ModuleResult(
        module=MODULE_NAME,
        status=score_to_status(score),
        score=max(0, score),
        confidence=DEFAULT_CONFIDENCE,
        findings=findings,
        details={
            "domain": hostname,
            "is_blacklisted": is_blacklisted,
            "blacklisted_on": flagged_lists,
            "static_feed_flagged": static_flagged,
            "total_lists_checked": len(DNSBL_LISTS),
        },
    )