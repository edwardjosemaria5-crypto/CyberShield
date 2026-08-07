from .scanner import scan_headers_module
from app.schemas.module_result import ModuleResult


def run_headers_check(domain: str) -> ModuleResult:
    return scan_headers_module(domain)