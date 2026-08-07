from app.modules.reputation.scanner import scan_reputation_module
from app.schemas.module_result import ModuleResult


def run_reputation_check(domain: str) -> ModuleResult:
    return scan_reputation_module(domain)