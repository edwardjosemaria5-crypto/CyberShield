"""AI security explanation layer.

Architecture:

    AnalysisResponse (deterministic, authoritative)
        -> ai_explanation.evidence.build_evidence()      (allowlisted, deterministic)
        -> AIExplanationService                          (one-shot, never raises)
              -> providers.<Provider>.generate()         (external model API)
        -> AIExplanation (validated, presentation-only)

The Risk Engine never calls into this package, and this package never
writes scoring fields. Everything here is derived presentation data.
"""

from app.modules.ai_explanation.base import AIExplanationProvider
from app.modules.ai_explanation.providers import build_provider

__all__ = ["AIExplanationProvider", "build_provider"]