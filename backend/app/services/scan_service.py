"""Scan orchestration service."""

import logging
from typing import Callable

from app.schemas.analysis_response import AnalysisResponse
from app.services.ai_explanation_service import AIExplanationService
from app.services.history_service import save_scan
from app.services.scan_manager import ScanManager

logger = logging.getLogger("cybershield.scan_service")


def run_scan(
    domain: str,
    *,
    explainer: Callable[[AnalysisResponse], AnalysisResponse] | None = None,
) -> AnalysisResponse:
    """Run the full URL intelligence pipeline on the target.

    The ScanManager is the single orchestrator the frontend / API talks to,
    and it owns the deterministic Risk Engine. After the deterministic
    result is complete, the optional AI explanation layer may attach a
    best-effort explanation; that layer is fully isolated and can neither
    change nor fail the deterministic result. A completed result is
    persisted afterwards; persistence failures are isolated and never
    change the response the client receives.

    ``explainer`` is injectable for tests. By default the configured
    :class:`AIExplanationService` is used (engineered to stand down when
    AI_ENABLED is false, a provider is missing, or the model misbehaves).
    """
    analysis = ScanManager().run(domain)
    if explainer is None:
        analysis = AIExplanationService().generate(analysis)
    else:
        analysis = explainer(analysis)
    try:
        save_scan(analysis)
    except Exception:  # noqa: BLE001 - history must never break the scan
        logger.exception(
            "Persisting scan %s failed; scan response is unaffected",
            analysis.scan_id,
        )
    return analysis