from typing import Any, Literal

from pydantic import BaseModel, Field

from app.schemas.finding import Finding

ModuleStatus = Literal["ok", "warning", "critical", "error"]


def score_to_status(score: int) -> ModuleStatus:
    """Map a module score (0-100) onto a canonical module status."""
    if score >= 90:
        return "ok"
    if score >= 70:
        return "warning"
    return "critical"


class ModuleResult(BaseModel):
    """Canonical result contract every analysis module MUST return.

    All modules return this exact structure; no module is allowed to
    return ad-hoc dictionaries. Module-specific detail data is preserved
    under ``details`` while ``findings`` carries structured findings.
    """

    module: str
    status: ModuleStatus = "ok"
    score: int = Field(default=100, ge=0, le=100)
    confidence: int = Field(default=100, ge=0, le=100)
    findings: list[Finding] = Field(default_factory=list)
    details: dict[str, Any] = Field(default_factory=dict)