from pydantic import BaseModel, Field

from app.schemas.verdict import Verdict


class RiskScore(BaseModel):
    """The aggregated trust score computed by the risk engine."""

    score: int = Field(default=100, ge=0, le=100)
    verdict: Verdict = Verdict.TRUSTED