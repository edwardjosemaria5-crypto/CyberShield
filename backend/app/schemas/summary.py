from pydantic import BaseModel, Field


class SeveritySummary(BaseModel):
    """Counts of findings per severity level for a completed scan."""

    critical: int = Field(default=0, ge=0)
    high: int = Field(default=0, ge=0)
    medium: int = Field(default=0, ge=0)
    low: int = Field(default=0, ge=0)
    info: int = Field(default=0, ge=0)