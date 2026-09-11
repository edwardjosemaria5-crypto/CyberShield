from fastapi import APIRouter, Path

from app.core.constants import MAX_TARGET_LENGTH
from app.modules.ssl.service import run_ssl_check
from app.schemas.module_result import ModuleResult

router = APIRouter(prefix="/ssl", tags=["ssl"])


@router.get("/{domain}")
def ssl_lookup(domain: str = Path(..., max_length=MAX_TARGET_LENGTH)) -> ModuleResult:
    return run_ssl_check(domain)