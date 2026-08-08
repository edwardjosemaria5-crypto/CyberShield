"""History endpoints: list completed scans and fetch full reports."""

from fastapi import APIRouter, HTTPException, Query

from app.schemas.analysis_response import AnalysisResponse
from app.schemas.history import ScanListResponse
from app.services import history_service

router = APIRouter(prefix="/history", tags=["history"])


@router.get("", response_model=ScanListResponse)
def list_history(
    limit: int = Query(20, ge=1, le=100, description="Maximum number of scans to return."),
    offset: int = Query(0, ge=0, description="Number of scans to skip."),
) -> ScanListResponse:
    items, total = history_service.list_scans(limit=limit, offset=offset)
    return ScanListResponse(items=items, total=total, limit=limit, offset=offset)


@router.get("/{scan_id}", response_model=AnalysisResponse)
def get_history_item(scan_id: str) -> AnalysisResponse:
    try:
        scan = history_service.get_scan(scan_id)
    except history_service.StoredAnalysisError:
        raise HTTPException(
            status_code=500,
            detail="The stored report could not be loaded.",
        ) from None
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found.")
    return scan