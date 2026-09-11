from fastapi import APIRouter, Path

from app.core.constants import MAX_TARGET_LENGTH
from app.modules.reputation.service import run_reputation_check
from app.schemas.module_result import ModuleResult

router = APIRouter(prefix="/reputation", tags=["reputation"])


@router.get("/{domain}")
def reputation_lookup(
    domain: str = Path(..., max_length=MAX_TARGET_LENGTH),
) -> ModuleResult:
    return run_reputation_check(domain)