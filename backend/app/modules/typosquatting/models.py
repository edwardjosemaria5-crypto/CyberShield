"""Models for the typosquatting intelligence module."""

from pydantic import BaseModel, Field


class BrandMatch(BaseModel):
    """A single brand comparison result.

    ``canonical_candidate`` is the candidate after substitution/homograph
    normalization; ``distance`` is the Levenshtein distance between the
    candidate and the brand after that normalization.
    """

    brand: str
    similarity: int = Field(ge=0, le=100)
    technique: str = "similar"
    distance: int = 0
    canonical_candidate: str = ""


class TyposquattingProfile(BaseModel):
    """Normalized typosquatting analysis for a domain."""

    domain: str
    sld: str
    matches: list[BrandMatch] = Field(default_factory=list)
    best_match: BrandMatch | None = None
