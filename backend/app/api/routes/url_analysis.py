from fastapi import APIRouter

from app.modules.url_analysis.service import URLAnalysisService
from app.schemas.module_result import ModuleResult

router = APIRouter(prefix="/url-analysis", tags=["url-analysis"])
service = URLAnalysisService()


@router.get("/{url:path}")
def analyze_url(url: str) -> ModuleResult:
    return service.scan(url)