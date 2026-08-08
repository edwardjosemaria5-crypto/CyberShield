"""Scan orchestration service."""

import logging

from app.schemas.analysis_response import AnalysisResponse
from app.services.history_service import save_scan
from app.services.scan_manager import ScanManager

logger = logging.getLogger("cybershield.scan_service")


def run_scan(domain: str) -> AnalysisResponse:
    """Run the full URL intelligence pipeline on the target.

    The ScanManager is the single orchestrator the frontend / API talks to.
    A completed result is persisted afterwards; persistence failures are
    isolated and never change the response the client receives.
    """
    analysis = ScanManager().run(domain)
    try:
        save_scan(analysis)
    except Exception:  # noqa: BLE001 - history must never break the scan
        logger.exception(
            "Persisting scan %s failed; scan response is unaffected",
            analysis.scan_id,
        )
    return analysis