from app.modules.phishing.scanner import scan_phishing_module
from app.schemas.module_result import ModuleResult


def run_phishing_check(domain: str) -> ModuleResult:
    return scan_phishing_module(domain)