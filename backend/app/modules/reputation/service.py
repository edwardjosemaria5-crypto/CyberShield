from app.modules.reputation.scanner import scan_reputation_module


def run_reputation_check(domain: str):
    return scan_reputation_module(domain)
