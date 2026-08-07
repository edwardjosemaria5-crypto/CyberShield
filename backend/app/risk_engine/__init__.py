"""Cross-module risk calculation components.

The risk engine consumes standardized :class:`ModuleResult` objects produced
by the ScanManager pipeline and produces the aggregated trust score, verdict,
and canonical :class:`AnalysisResponse`.
"""

from app.risk_engine.engine import calculate_risk_score, calculate_scan_risk
from app.risk_engine.scorer import compute_confidence, compute_trust_score
from app.risk_engine.verdict import Verdict

__all__ = [
    "Verdict",
    "calculate_risk_score",
    "calculate_scan_risk",
    "compute_confidence",
    "compute_trust_score",
]
