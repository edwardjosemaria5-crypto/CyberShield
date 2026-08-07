from app.modules.blacklist.scanner import scan_blacklist_module
from app.schemas.module_result import ModuleResult


def run_blacklist_check(domain: str) -> ModuleResult:
    return scan_blacklist_module(domain)