from fastapi import APIRouter, Path

from app.core.constants import MAX_TARGET_LENGTH
from app.modules.ports.service import run_ports_check
from app.schemas.module_result import ModuleResult

router = APIRouter(prefix="/ports", tags=["ports"])


@router.get("/{host:path}")
def ports_scan(host: str = Path(..., max_length=MAX_TARGET_LENGTH)) -> ModuleResult:
    return run_ports_check(host)