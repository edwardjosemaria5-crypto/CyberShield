from fastapi import APIRouter

from app.modules.typosquatting.service import run_typosquatting_check
from app.schemas.module_result import ModuleResult

router = APIRouter(prefix="/typosquatting", tags=["typosquatting"])


@router.get("/{domain}")
def typosquatting_lookup(domain: str) -> ModuleResult:
    return run_typosquatting_check(domain)