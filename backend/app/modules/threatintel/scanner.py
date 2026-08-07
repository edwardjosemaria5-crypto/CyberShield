from app.modules.threatintel.blacklist import get_blacklist_data
from app.modules.threatintel.malware import get_malware_data
from app.modules.threatintel.phishing import get_phishing_data
from app.schemas.finding import Finding
from app.schemas.module_result import ModuleResult, score_to_status
from .rules import (
    DEFAULT_CONFIDENCE,
    FEED_FLAGGED_PENALTY,
    MALWARE_PENALTY,
    MODULE_NAME,
    PHISHING_PENALTY,
)


def scan_threatintel_module(domain: str) -> ModuleResult:
    """Scan target domain across aggregated Threat Intelligence feeds (Phishing, Malware, Blacklists)."""
    hostname = domain.replace("https://", "").replace("http://", "").split("/")[0].split(":")[0]

    phishing_data = get_phishing_data(hostname)
    malware_data = get_malware_data(hostname)
    blacklist_data = get_blacklist_data(hostname)

    score = 100
    findings: list[Finding] = []

    if phishing_data["is_phishing_suspect"]:
        score -= PHISHING_PENALTY
        findings.append(
            Finding(
                title="Phishing pattern detected",
                severity="high",
                description=f"Phishing keyword pattern detected ({', '.join(phishing_data['detected_keywords'])}).",
                recommendation="Avoid interacting with the domain; report it to a security team.",
            )
        )

    if malware_data["is_malware_suspect"]:
        score -= MALWARE_PENALTY
        findings.append(
            Finding(
                title="Malware pattern flagged",
                severity="critical",
                description=f"Malware host pattern flagged ({malware_data['suspicious_pattern']}).",
                recommendation="Block the domain and scan any machines that accessed it.",
            )
        )

    if blacklist_data["is_flagged"]:
        score -= FEED_FLAGGED_PENALTY
        findings.append(
            Finding(
                title="Threat feed flag",
                severity="critical",
                description="Domain listed on active global threat intelligence feed.",
                recommendation="Treat the domain as malicious until verified otherwise.",
            )
        )

    score = max(0, min(100, score))

    return ModuleResult(
        module=MODULE_NAME,
        status=score_to_status(score),
        score=score,
        confidence=DEFAULT_CONFIDENCE,
        findings=findings,
        details={
            "domain": hostname,
            "phishing_analysis": phishing_data,
            "malware_analysis": malware_data,
            "threat_feed_status": blacklist_data,
        },
    )