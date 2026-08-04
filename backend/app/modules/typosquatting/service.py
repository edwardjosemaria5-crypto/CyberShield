from app.modules.typosquatting.scanner import scan_typosquatting_module


def run_typosquatting_check(domain: str):
    return scan_typosquatting_module(domain)
