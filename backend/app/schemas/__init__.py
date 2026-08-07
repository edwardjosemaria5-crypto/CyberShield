"""Shared Pydantic schemas for the CyberShield API.

These are the canonical contracts used across every module, the
ScanManager orchestrator, and the risk engine. No module may define its
own ad-hoc response shape anymore.
"""

from app.schemas.analysis_request import AnalysisRequest
from app.schemas.analysis_response import AnalysisResponse
from app.schemas.finding import Finding
from app.schemas.module_result import ModuleResult, score_to_status
from app.schemas.response import ResponseModel
from app.schemas.risk_score import RiskScore
from app.schemas.summary import SeveritySummary
from app.schemas.verdict import Verdict, verdict_for_score

__all__ = [
    "AnalysisRequest",
    "AnalysisResponse",
    "Finding",
    "ModuleResult",
    "ResponseModel",
    "RiskScore",
    "SeveritySummary",
    "Verdict",
    "score_to_status",
    "verdict_for_score",
]
