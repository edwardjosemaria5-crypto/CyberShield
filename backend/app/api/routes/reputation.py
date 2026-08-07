from fastapi import APIRouter

from app.modules.reputation.service import run_reputation_check
from app.schemas.module_result import ModuleResult

router = APIRouter(prefix="/reputation", tags=["reputation"])


@router.get("/{domain}")
def reputation_lookup(domain: str) -> ModuleResult:
    return run_reputation_check(domain)