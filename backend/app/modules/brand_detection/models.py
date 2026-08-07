"""Models for the brand detection module."""

from pydantic import BaseModel, Field


class BrandSignal(BaseModel):
    """A single detected brand/impersonation signal."""

    brand: str
    matched_alias: str
    context: str = "label"
    suspicious_terms: list[str] = Field(default_factory=list)


class BrandDetectionProfile(BaseModel):
    """Normalized brand-detection result for a domain."""

    domain: str
    sld: str
    labels: list[str] = Field(default_factory=list)
    signals: list[BrandSignal] = Field(default_factory=list)
    suspicious_terms: list[str] = Field(default_factory=list)
    hyphens: int = 0
    #: Brand + suspicious-term combination detected (strong impersonation).
    brand_term_combo: bool = False
    #: Best typosquatting-style similarity match (if any).
    similarity_match: dict | None = None
