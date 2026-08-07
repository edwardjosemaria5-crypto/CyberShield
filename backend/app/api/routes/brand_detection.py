from fastapi import APIRouter

from app.modules.brand_detection.service import run_brand_detection_check
from app.schemas.module_result import ModuleResult

router = APIRouter(prefix="/brand-detection", tags=["brand-detection"])


@router.get("/{domain}")
def brand_detection_lookup(domain: str) -> ModuleResult:
    return run_brand_detection_check(domain)