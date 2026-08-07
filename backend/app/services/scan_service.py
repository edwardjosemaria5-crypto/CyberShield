from app.schemas.analysis_response import AnalysisResponse
from app.services.scan_manager import ScanManager


def run_scan(domain: str) -> AnalysisResponse:
    """Run the full URL intelligence pipeline on the target.

    The ScanManager is the single orchestrator the frontend / API talks to.
    """
    return ScanManager().run(domain)