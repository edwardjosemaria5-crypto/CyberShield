from app.modules.threatintel.scanner import scan_threatintel_module
from app.schemas.module_result import ModuleResult


def run_threatintel_check(domain: str) -> ModuleResult:
    return scan_threatintel_module(domain)