"""Risk-engine facade responsible for producing an AnalysisResponse.

Responsibilities:
- receive every ModuleResult produced by the ScanManager
- aggregate them into a single analysis
- delegate score calculation to the scorer
- build the canonical :class:`AnalysisResponse`
"""

import logging

from app.risk_engine.scorer import compute_confidence, compute_trust_score
from app.schemas.analysis_response import AnalysisResponse
from app.schemas.module_result import ModuleResult
from app.schemas.summary import SeveritySummary

logger = logging.getLogger("cybershield.risk_engine")

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def severity_summary(findings: list) -> SeveritySummary:
    """Count findings per severity level into a :class:`SeveritySummary`."""
    counts: dict[str, int] = {level: 0 for level in SEVERITY_ORDER}
    for finding in findings:
        counts[finding.severity] = counts.get(finding.severity, 0) + 1
    return SeveritySummary(**counts)


def calculate_risk_score(results: dict[str, ModuleResult]) -> AnalysisResponse:
    """Aggregate module results and return a canonical analysis response.

    ``module_results`` order is preserved into ``modules`` so the response is
    stable regardless of the concurrent completion order of the scanners.
    ``target``/``normalized_url``/``domain`` and `scan_id`/timestamps are
    filled in by the ScanManager after the engine returns.
    """
    risk = compute_trust_score(results)
    confidence = compute_confidence(results)
    all_findings = [
        finding
        for result in results.values()
        for finding in result.findings
    ]
    all_findings.sort(key=lambda f: SEVERITY_ORDER.get(f.severity, 4))

    summary = severity_summary(all_findings)

    logger.info(
        "Aggregated %d modules -> trust score %d, confidence %d (%s)",
        len(results),
        risk.score,
        confidence,
        risk.verdict.value,
    )

    return AnalysisResponse(
        target="",
        normalized_url="",
        domain="",
        trust_score=risk.score,
        confidence=confidence,
        verdict=risk.verdict,
        summary=summary,
        modules=list(results.values()),
        findings=all_findings,
    )


def calculate_scan_risk(headers_result: dict, dns_result: dict, whois_result: dict) -> dict:
    """Legacy compatibility wrapper retained for the original /scan contract.

    Kept until upstream callers are fully migrated to ModuleResult-based
    aggregation. It normalizes legacy dict payloads into the new pipeline
    without re-running any network scans.
    """
    collected = {
        "headers": _legacy_to_result(headers_result, "headers"),
        "dns": _legacy_to_result(dns_result, "dns"),
        "whois": _legacy_to_result(whois_result, "whois"),
    }
    response = calculate_risk_score(collected)
    return {
        "security_score": response.trust_score,
        "overall_risk": response.verdict.value,
        "issues": [f.title for f in response.findings if f.severity in {"critical", "high"}],
    }


def _legacy_to_result(payload: dict, module: str) -> ModuleResult:
    from app.schemas.finding import Finding
    from app.schemas.module_result import score_to_status

    if isinstance(payload, ModuleResult):
        return payload
    if "error" in payload:
        score = 50
        findings = [
            Finding(title=payload["error"], severity="high", description=payload["error"])
        ]
    else:
        score = payload.get("security_score", payload.get("reputation_score", 100))
        if "issues" in payload:
            findings = [
                Finding(title=issue, severity="medium", description=issue)
                for issue in payload["issues"]
            ]
        else:
            findings = []
    return ModuleResult(
        module=module,
        status=score_to_status(score),
        score=score,
        confidence=100,
        findings=findings,
        details=payload,
    )