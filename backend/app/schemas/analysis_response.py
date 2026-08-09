from pydantic import BaseModel, Field

from app.schemas.ai_explanation import AIExplanation
from app.schemas.finding import Finding
from app.schemas.module_result import ModuleResult
from app.schemas.summary import SeveritySummary
from app.schemas.verdict import Verdict


class AnalysisResponse(BaseModel):
    """Canonical response returned by the ScanManager and risk engine.

    ``trust_score``, ``confidence``, ``verdict`` and ``summary`` are produced
    by the risk engine; ``scan_id`` and the timestamps are stamped by the
    ScanManager. ``modules`` preserves registry order regardless of the
    runtime completion order of the concurrent scanners.

    ``ai_explanation`` is a nullable, read-only sidecar: when present it is
    AI-derived presentation data only, and never influences any scoring
    field above. Absence (``null``) is a normal state (disabled/unavailable
    AI) and the deterministic analysis remains fully valid.
    """

    scan_id: str = Field(default="", description="Unique scan identifier (CS-YYYY-XXXXXXXXXXXX).")
    target: str
    normalized_url: str
    domain: str
    started_at: str = Field(default="", description="ISO-8601 pipeline start timestamp.")
    completed_at: str = Field(default="", description="ISO-8601 pipeline completion timestamp.")
    trust_score: int = Field(default=0, ge=0, le=100)
    confidence: int = Field(default=0, ge=0, le=100)
    verdict: Verdict = Verdict.TRUSTED
    summary: SeveritySummary = Field(default_factory=SeveritySummary)
    modules: list[ModuleResult] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    ai_explanation: AIExplanation | None = Field(
        default=None,
        description="Optional AI-generated explanation; never affects scoring.",
    )