import requests

from app.schemas.finding import Finding
from app.schemas.module_result import ModuleResult, score_to_status
from app.utils.networking import validate_public_host
from .rules import (
    DEFAULT_CONFIDENCE,
    HEADER_DEFINITIONS,
    HEADER_RECOMMENDATIONS,
    MODULE_NAME,
    grade_for_score,
)


class BlockedTargetError(requests.RequestException):
    """Raised when a target is refused by the outbound safety guard."""


def _follow_redirects_safely(initial_url: str, timeout: int = 10, max_hops: int = 4) -> "requests.Response":
    """Fetch a URL following at most ``max_hops`` redirects, validating that
    every hop targets a public host. A hop toward a private/reserved address
    aborts the request instead of following it."""
    hop_url = initial_url
    for _ in range(max_hops):
        blocked = validate_public_host(hop_url)
        if blocked:
            raise BlockedTargetError(blocked)
        response = requests.get(hop_url, timeout=timeout, allow_redirects=False)
        if response.is_redirect and "location" in response.headers:
            hop_url = requests.utils.requote_uri(
                requests.compat.urljoin(hop_url, response.headers["location"])
            )
            continue
        return response
    raise requests.TooManyRedirects("Too many redirects")


def scan_headers_module(domain: str) -> ModuleResult:
    """Scan a website for the existing set of HTTP security headers."""
    url = domain if domain.startswith(("http://", "https://")) else f"https://{domain}"
    try:
        response = _follow_redirects_safely(url)
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