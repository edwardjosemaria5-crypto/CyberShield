from fastapi import APIRouter, Path

from app.core.constants import MAX_TARGET_LENGTH
from app.modules.threatintel.service import run_threatintel_check
from app.schemas.module_result import ModuleResult

router = APIRouter(prefix="/threatintel", tags=["threatintel"])


@router.get("/{domain}")
def threatintel_lookup(
    domain: str = Path(..., max_length=MAX_TARGET_LENGTH),
) -> ModuleResult:
    return run_threatintel_check(domain)