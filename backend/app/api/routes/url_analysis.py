from fastapi import APIRouter

from app.modules.url_analysis.service import URLAnalysisService

router = APIRouter(prefix="/url-analysis", tags=["url-analysis"])
service = URLAnalysisService()


@router.get("/{url:path}")
def analyze_url(url: str):
    return service.scan(url)
