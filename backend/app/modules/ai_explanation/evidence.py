"""Evidence package construction for the AI explanation layer.

Converts a completed, authoritative
:class:`~app.schemas.analysis_response.AnalysisResponse` into a controlled,
deterministic dictionary that the AI provider receives. Everything here is
an **allowlist** — raw module ``details`` dictionaries, credentials, API
keys and other application state are deliberately never copied in.

Guarantees (tested):

- deterministic: two identical analyses produce byte-identical evidence
- allowlist only: the output contains exclusively the fields declared here
- secrets excluded: no keys/credentials/auth material can ever appear
- score-blind: the engineered ``trust_score``, ``confidence`` and
  ``verdict`` are deliberately NOT included — the model must never see or
  restate risk-engine numbers
"""

from typing import Any

from app.schemas.analysis_response import AnalysisResponse

#: Findings capped per scan; smaller inputs pass fully through.
MAX_FINDINGS = 20

#: Longest single evidence string sent to the model (characters).
MAX_EVIDENCE_LEN = 240


def _clip(text: str, limit: int) -> str:
    text = str(text or "")
    return text if len(text) <= limit else f"{text[: limit - 3]}..."


def build_evidence(analysis: AnalysisResponse) -> dict[str, Any]:
    """Build the frozen evidence package the AI provider may read."""
    modules = [
        {
            "module": result.module,
            "status": result.status,
            "score": result.score,
            "confidence": result.confidence,
        }
        for result in analysis.modules
    ]

    findings = [
        {
            "title": finding.title,
            "severity": finding.severity,
            "description": _clip(finding.description, MAX_EVIDENCE_LEN),
            "explanation": _clip(finding.explanation, MAX_EVIDENCE_LEN),
            "recommendation": _clip(
                finding.recommendation, MAX_EVIDENCE_LEN
            ) if finding.recommendation else "",
            "evidence": _clip(finding.evidence, MAX_EVIDENCE_LEN),
        }
        for finding in analysis.findings[:MAX_FINDINGS]
    ]

    evidence: dict[str, Any] = {
        "target": analysis.target,
        "normalized_url": analysis.normalized_url,
        "domain": analysis.domain,
        "severity_counts": analysis.summary.model_dump(),
        "modules": modules,
        "findings": findings,
        "threat_intel": _threat_intel_extract(analysis),
    }
    return evidence


def _threat_intel_extract(analysis: AnalysisResponse) -> dict[str, Any] | None:
    """Extract the correlated threat-intelligence view (allowlist).

    Reads only the normalized ``threat_intel_correlation`` block produced
    by the scanner's correlation stage; per-provider raw payloads and the
    module's ``details`` dict are never copied.
    """
    for result in analysis.modules:
        if result.module != "threatintel":
            continue
        corr = (result.details or {}).get("threat_intel_correlation")
        if not isinstance(corr, dict):
            return None
        signals = []
        for signal in corr.get("signals") or []:
            if not isinstance(signal, dict):
                continue
            signals.append(
                {
                    "provider": signal.get("provider"),
                    "status": signal.get("status"),
                    "malicious": bool(signal.get("malicious")),
                    "suspicious": bool(signal.get("suspicious")),
                    "confidence": signal.get("confidence", 0),
                    "categories": signal.get("categories") or [],
                }
            )
        return {
            "available_count": corr.get("available_count", 0),
            "malicious_count": corr.get("malicious_count", 0),
            "suspicious_count": corr.get("suspicious_count", 0),
            "clean_count": corr.get("clean_count", 0),
            "unavailable_count": corr.get("unavailable_count", 0),
            "agreement": corr.get("agreement"),
            "consensus": corr.get("consensus"),
            "conflict": bool(corr.get("conflict")),
            "malicious_confidence": corr.get("malicious_confidence", 0),
            "suspicious_confidence": corr.get("suspicious_confidence", 0),
            "signals": signals,
        }
    return None