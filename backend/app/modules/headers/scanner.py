import requests

from app.schemas.finding import Finding
from app.schemas.module_result import ModuleResult, score_to_status
from .rules import (
    DEFAULT_CONFIDENCE,
    HEADER_DEFINITIONS,
    HEADER_RECOMMENDATIONS,
    MODULE_NAME,
    grade_for_score,
)


def scan_headers_module(domain: str) -> ModuleResult:
    """Scan a website for the existing set of HTTP security headers."""
    url = domain if domain.startswith(("http://", "https://")) else f"https://{domain}"
    try:
        response = requests.get(url, timeout=10)
    except requests.RequestException as exc:
        return ModuleResult(
            module=MODULE_NAME,
            status="error",
            score=50,
            confidence=100,
            findings=[
                Finding(
                    title="Header scan failed",
                    severity="high",
                    description=f"Unable to fetch headers: {exc}",
                    recommendation="Ensure the target is reachable over HTTPS.",
                )
            ],
            details={"url": url, "error": str(exc)},
        )

    results: dict[str, dict] = {}
    findings: list[Finding] = []

    for header, (severity, weight) in HEADER_DEFINITIONS.items():
        value = response.headers.get(header)
        if value:
            results[header] = {"status": "Present", "risk": "None", "value": value}
        else:
            results[header] = {
                "status": "Missing",
                "risk": severity,
                "recommendation": HEADER_RECOMMENDATIONS[header],
            }
            findings.append(
                Finding(
                    title=f"Missing {header}",
                    severity=severity,
                    description=f"The {header} security header is not set.",
                    recommendation=HEADER_RECOMMENDATIONS[header],
                )
            )

    score = sum(
        weight for header, (_, weight) in HEADER_DEFINITIONS.items()
        if results[header]["status"] == "Present"
    )
    grade = grade_for_score(score)
    present_headers = sum(result["status"] == "Present" for result in results.values())

    return ModuleResult(
        module=MODULE_NAME,
        status=score_to_status(score),
        score=score,
        confidence=DEFAULT_CONFIDENCE,
        findings=findings,
        details={
            "url": response.url,
            "grade": grade,
            "summary": {
                "present_headers": present_headers,
                "missing_headers": len(results) - present_headers,
            },
            "security_headers": results,
        },
    )