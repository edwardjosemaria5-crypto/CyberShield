from fastapi import APIRouter

from app.modules.ports.service import run_ports_check
from app.schemas.module_result import ModuleResult

router = APIRouter(prefix="/ports", tags=["ports"])


@router.get("/{host:path}")
def ports_scan(host: str) -> ModuleResult:
    return run_ports_check(host)