from fastapi import APIRouter

from app.modules.ssl.service import run_ssl_check
from app.schemas.module_result import ModuleResult

router = APIRouter(prefix="/ssl", tags=["ssl"])


@router.get("/{domain}")
def ssl_lookup(domain: str) -> ModuleResult:
    return run_ssl_check(domain)