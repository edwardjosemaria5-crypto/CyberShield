from typing import Literal

from pydantic import BaseModel, Field

Severity = Literal["critical", "high", "medium", "low", "info"]


class Finding(BaseModel):
    """A single security or trust finding produced by a module scan.

    CyberShield is an educational platform: every finding explains what was
    detected, why it matters, the evidence behind it, and how to remediate.
    The optional enrichment fields default to empty/100 so legacy producers
    remain valid.
    """

    title: str
    severity: Severity = "info"
    description: str = Field(default="")
    explanation: str = Field(default="", description="Why this finding matters.")
    recommendation: str = Field(default="")
    evidence: str = Field(default="", description="Concrete data supporting the finding.")
    confidence: int = Field(default=100, ge=0, le=100)