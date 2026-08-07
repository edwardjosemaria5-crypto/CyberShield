from app.schemas.finding import Finding
from app.schemas.module_result import ModuleResult, score_to_status
from .rules import (
    DEEP_SUBDOMAIN_PENALTY,
    DEFAULT_CONFIDENCE,
    EXCESSIVE_HYPHENS_PENALTY,
    MAX_HYPHENS,
    MAX_SUBDOMAIN_DEPTH,
    MODULE_NAME,
    SUSPICIOUS_KEYWORD_PENALTY,
    SUSPICIOUS_KEYWORDS,
)


def scan_phishing_module(domain: str) -> ModuleResult:
    """Analyze domain structure for phishing indicators (keywords, depth, hyphens).

    Placeholder implementation for the future phishing intelligence provider;
    currently based on deterministic heuristics only.
    """
    hostname = domain.replace("https://", "").replace("http://", "").split("/")[0].split(":")[0].lower()

    detected_keywords = [kw for kw in SUSPICIOUS_KEYWORDS if kw in hostname]
    subdomain_count = max(0, hostname.count(".") - 1)
    hyphen_count = hostname.count("-")

    score = 100
    findings: list[Finding] = []

    if detected_keywords:
        score -= SUSPICIOUS_KEYWORD_PENALTY
        findings.append(
            Finding(
                title="Phishing keywords in domain",
                severity="high",
                description=f"Domain contains suspicious keywords: {', '.join(detected_keywords)}.",
                recommendation="Verify the domain's legitimacy; phishing sites mimic trusted brands.",
            )
        )

    if subdomain_count > MAX_SUBDOMAIN_DEPTH:
        score -= DEEP_SUBDOMAIN_PENALTY
        findings.append(
            Finding(
                title="Deep subdomain structure",
                severity="medium",
                description="The domain uses an unusually deep subdomain chain.",
                recommendation="Inspect the full hostname; attackers hide behind deep subdomains.",
            )
        )

    if hyphen_count > MAX_HYPHENS:
        score -= EXCESSIVE_HYPHENS_PENALTY
        findings.append(
            Finding(
                title="Excessive hyphens in domain",
                severity="medium",
                description="The domain contains many hyphens, a common phishing pattern.",
                recommendation="Confirm the domain is legitimate before trusting it.",
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
            "is_phishing_suspect": score < 100,
            "detected_keywords": detected_keywords,
            "subdomain_depth": subdomain_count,
            "hyphen_count": hyphen_count,
        },
    )