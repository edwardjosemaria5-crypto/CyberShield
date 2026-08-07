from fastapi import APIRouter

from app.modules.threatintel.service import run_threatintel_check
from app.schemas.module_result import ModuleResult

router = APIRouter(prefix="/threatintel", tags=["threatintel"])


@router.get("/{domain}")
def threatintel_lookup(domain: str) -> ModuleResult:
    return run_threatintel_check(domain)