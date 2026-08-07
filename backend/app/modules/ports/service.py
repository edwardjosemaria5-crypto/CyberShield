from app.modules.ports.scanner import scan_ports_module
from app.schemas.module_result import ModuleResult


def run_ports_check(host: str) -> ModuleResult:
    return scan_ports_module(host)