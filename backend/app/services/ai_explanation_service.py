"""AI explanation service.

Pipeline (explanation-only, never scoring):

    1. Build the allowlisted evidence package from the completed analysis.
    2. Ask the configured AI provider to explain it (one attempt).
    3. Strictly validate the model output against ``AIExplanation``.
    4. If anything fails at any step: return the analysis UNCHANGED and log.

Critical invariant (enforced by the test suite): the deterministic
``AnalysisResponse`` — trust score, verdict, module scores, findings,
recommendations — is byte-identical whether the AI succeeds, fails, or is
disabled. ``ai_explanation`` is only ever a nullable sidecar added to a
copy of the response.

The Risk Engine never calls this service.
"""

import logging

from pydantic import ValidationError

from app.core.config import AI_ENABLED
from app.modules.ai_explanation.base import AIExplanationProvider
from app.modules.ai_explanation.evidence import build_evidence
from app.modules.ai_explanation.providers import get_default_provider
from app.schemas.ai_explanation import AIExplanation
from app.schemas.analysis_response import AnalysisResponse

logger = logging.getLogger("cybershield.ai_explanation")


class AIExplanationService:
    """Best-effort AI explanation layer; never fails a scan."""

    def __init__(
        self,
        provider: AIExplanationProvider | None = None,
        enabled: bool = AI_ENABLED,
    ) -> None:
        self._provider = provider if provider is not None else get_default_provider()
        self._enabled = enabled

    @property
    def enabled(self) -> bool:
        return self._enabled

    def generate(
        self,
        analysis: AnalysisResponse,
        provider: AIExplanationProvider | None = None,
    ) -> AnalysisResponse:
        """Attempt to attach an AI explanation; returns a valid analysis.

        ``provider`` override is honored (tests inject fakes); otherwise the
        configured provider is used. Any failure path returns the input
        analysis unchanged (never raises).
        """
        if not self._enabled:
            return analysis

        active = provider if provider is not None else self._provider
        if active is None or not active.is_configured:
            logger.info("AI provider unavailable; explanation skipped.")
            return analysis

        try:
            evidence = build_evidence(analysis)
        except Exception:  # noqa: BLE001 - evidence building must never break a scan
            logger.exception("Failed to build AI evidence; explanation skipped.")
            return analysis

        try:
            raw = active.generate(evidence)
        except Exception:  # noqa: BLE001 - provider must never break a scan
            logger.exception("AI provider raised unexpectedly; explanation skipped.")
            return analysis

        if raw is None:
            logger.info("AI provider produced no output; explanation skipped.")
            return analysis

        try:
            explanation = _validate(raw)
        except Exception:  # noqa: BLE001 - invalid model output must never break a scan
            logger.warning("AI provider output failed validation; explanation discarded.")
            return analysis

        return analysis.model_copy(update={"ai_explanation": explanation})


def _validate(output: dict) -> AIExplanation:
    """Strict validating of model output against the schema.

    Accepts extras silently but requires every core field to exist and
    satisfy the documented constraints; a single invalid element discards
    the whole explanation (never a partial attachment).
    """
    if not isinstance(output, dict):
        raise ValidationError("AI output is not an object", AIExplanation)
    return AIExplanation.model_validate(output)