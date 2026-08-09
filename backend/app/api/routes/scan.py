from fastapi import APIRouter, HTTPException

from app.schemas.analysis_request import AnalysisRequest
from app.services.scan_service import run_scan

router = APIRouter(prefix="/scan", tags=["scan"])

# Matches the POST body bound in AnalysisRequest; keeps the GET path variant
# from driving unbounded strings into the pipeline or the database.
MAX_TARGET_LENGTH = 2048


@router.get("/{target:path}")
def scan_target(target: str):
    if len(target) > MAX_TARGET_LENGTH:
        raise HTTPException(
            status_code=422,
            detail=f"Target is too long (max {MAX_TARGET_LENGTH} characters).",
        )
    return run_scan(target)


@router.post("")
def scan_target_post(request: AnalysisRequest):
    return run_scan(request.target)