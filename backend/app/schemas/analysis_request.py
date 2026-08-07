from pydantic import BaseModel, Field


class AnalysisRequest(BaseModel):
    """Inbound request for a full URL intelligence analysis."""

    target: str = Field(..., min_length=1, max_length=2048)