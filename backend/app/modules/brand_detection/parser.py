"""Normalize raw brand-detection data into a :class:`BrandDetectionProfile`."""

from app.modules.brand_detection.models import BrandDetectionProfile, BrandSignal


def parse_brand_profile(raw: dict) -> BrandDetectionProfile:
    """Build a profile from the raw scanner payload."""
    return BrandDetectionProfile(
        domain=raw.get("domain", ""),
        sld=raw.get("sld", ""),
        labels=raw.get("labels", []),
        signals=[BrandSignal(**s) for s in raw.get("signals", [])],
        suspicious_terms=raw.get("suspicious_terms", []),
        hyphens=raw.get("hyphens", 0),
        brand_term_combo=raw.get("brand_term_combo", False),
        similarity_match=raw.get("similarity_match"),
    )