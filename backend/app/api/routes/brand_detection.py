from fastapi import APIRouter, Path

from app.core.constants import MAX_TARGET_LENGTH
from app.modules.brand_detection.service import run_brand_detection_check
from app.schemas.module_result import ModuleResult

router = APIRouter(prefix="/brand-detection", tags=["brand-detection"])


@router.get("/{domain}")
def brand_detection_lookup(
    domain: str = Path(..., max_length=MAX_TARGET_LENGTH),
) -> ModuleResult:
    return run_brand_detection_check(domain)