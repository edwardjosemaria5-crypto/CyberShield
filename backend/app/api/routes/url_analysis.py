from fastapi import APIRouter, Path

from app.core.constants import MAX_TARGET_LENGTH
from app.modules.url_analysis.service import URLAnalysisService
from app.schemas.module_result import ModuleResult

router = APIRouter(prefix="/url-analysis", tags=["url-analysis"])
service = URLAnalysisService()


@router.get("/{url:path}")
def analyze_url(url: str = Path(..., max_length=MAX_TARGET_LENGTH)) -> ModuleResult:
    return service.scan(url)