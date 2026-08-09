"""AI security-explanation contract.

The AI milestone is strictly an *explanation layer*. This schema holds the
derived, presentation-only explanation data produced by an external model.

Authority invariant (enforced by tests):

- ``AIExplanation`` NEVER feeds back into the Risk Engine, the trust score,
  the verdict, module scores, threat-intelligence results, findings or
  recommendations.
- ``AnalysisResponse`` remains the source of truth; ``ai_explanation`` is a
  nullable, read-only sidecar field. Absence (``null``) is a perfectly
  valid state — an unavailable or disabled AI must never break a scan.
- The model must be instructed to use only the supplied evidence; the
  structured response below is validated before it is ever stored, and
  anything failing validation is discarded (the scan result is untouched).

The schema deliberately does not carry scores or verdicts: the model never
reports the score/verdict, and CyberShield never asks it to.
"""

from pydantic import BaseModel, Field


class AIExplanation(BaseModel):
    """One validated, AI-generated security explanation for a completed scan."""

    summary: str = Field(
        ...,
        description="One or two sentence summary of the assessment.",
        min_length=1,
        max_length=800,
    )
    why_risky: str = Field(
        ...,
        description="Human-readable account of why the evidence produced this assessment.",
        min_length=1,
        max_length=2000,
    )
    key_risk_factors: list[str] = Field(
        ...,
        description="Distinct, evidence-backed risk factors (bullets).",
        min_length=1,
        max_length=12,
    )
    technical_explanation: str = Field(
        ...,
        description="More technical walkthrough tied to the supplied findings.",
        min_length=1,
        max_length=2500,
    )
    recommended_actions: list[str] = Field(
        ...,
        description="Practical next steps derived from the scan evidence.",
        min_length=1,
        max_length=12,
    )
    generated_by: str = Field(
        default="ai-external",
        description="Provider label surfaced in the UI ('AI-external')."
        "Never implied to be the source of the trust score.",
        max_length=80,
    )