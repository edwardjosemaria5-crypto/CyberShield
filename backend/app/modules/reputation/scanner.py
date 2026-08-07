from app.modules.reputation.blacklist import get_blacklist_status
from app.modules.reputation.domain_age import get_domain_age
from app.modules.reputation.popularity import get_popularity
from app.schemas.finding import Finding
from app.schemas.module_result import ModuleResult, score_to_status
from .rules import (
    BLACKLISTED_PENALTY,
    DEFAULT_CONFIDENCE,
    HIGH_RISK_TLD_PENALTY,
    MODULE_NAME,
    NEWLY_REGISTERED_PENALTY,
)


def scan_reputation_module(domain: str) -> ModuleResult:
    """Scan target domain for reputation signals including blacklist status, age, and TLD trust."""
    hostname = domain.replace("https://", "").replace("http://", "").split("/")[0].split(":")[0]

    age_data = get_domain_age(hostname)
    blacklist_data = get_blacklist_status(hostname)
    popularity_data = get_popularity(hostname)

    score = 100
    findings: list[Finding] = []

    if blacklist_data["is_blacklisted"]:
        score -= BLACKLISTED_PENALTY
        findings.append(
            Finding(
                title="Domain blacklisted",
                severity="high",
                description=f"Domain listed on {len(blacklist_data['blacklisted_on'])} DNS blocklists.",
                recommendation="Investigate the blocklist entries and request delisting once resolved.",
            )
        )

    if age_data["newly_registered"]:
        score -= NEWLY_REGISTERED_PENALTY
        findings.append(
            Finding(
                title="Newly registered domain",
                severity="medium",
                description=f"Domain is newly registered ({age_data['age_days']} days old).",
                recommendation="Treat young domains with caution; attackers favor fresh registrations.",
            )
        )

    if popularity_data["tld_risk"] == "High":
        score -= HIGH_RISK_TLD_PENALTY
        findings.append(
            Finding(
                title="High-risk TLD",
                severity="medium",
                description=f"Domain uses high-risk TLD (.{popularity_data['tld']}).",
                recommendation="Verify the domain's identity; some TLDs are associated with abuse.",
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
            "domain_age": age_data,
            "blacklist": blacklist_data,
            "popularity": popularity_data,
        },
    )