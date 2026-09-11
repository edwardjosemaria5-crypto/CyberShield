from fastapi import APIRouter, Path

from app.core.constants import MAX_TARGET_LENGTH
from app.modules.typosquatting.service import run_typosquatting_check
from app.schemas.module_result import ModuleResult

router = APIRouter(prefix="/typosquatting", tags=["typosquatting"])


@router.get("/{domain}")
def typosquatting_lookup(
    domain: str = Path(..., max_length=MAX_TARGET_LENGTH),
) -> ModuleResult:
    return run_typosquatting_check(domain)