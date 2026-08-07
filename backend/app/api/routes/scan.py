from fastapi import APIRouter

from app.schemas.analysis_request import AnalysisRequest
from app.services.scan_service import run_scan

router = APIRouter(prefix="/scan", tags=["scan"])


@router.get("/{target:path}")
def scan_target(target: str):
    return run_scan(target)


@router.post("")
def scan_target_post(request: AnalysisRequest):
    return run_scan(request.target)