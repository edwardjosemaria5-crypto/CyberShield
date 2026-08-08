"""Response schemas for the scan history API."""

from pydantic import BaseModel, Field

from app.schemas.summary import SeveritySummary
from app.schemas.verdict import Verdict


class ScanListItem(BaseModel):
    """Summary row for one completed scan."""

    scan_id: str
    target: str
    normalized_url: str = Field(default="")
    domain: str = Field(default="")
    trust_score: int = Field(default=0)
    confidence: int = Field(default=0)
    verdict: Verdict = Verdict.TRUSTED
    summary: SeveritySummary = Field(default_factory=SeveritySummary)
    completed_at: str = Field(default="")


class ScanListResponse(BaseModel):
    """Paginated list of completed scans."""

    items: list[ScanListItem]
    total: int
    limit: int
    offset: int