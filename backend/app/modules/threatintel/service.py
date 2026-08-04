from app.modules.threatintel.scanner import scan_threatintel_module


def run_threatintel_check(domain: str):
    return scan_threatintel_module(domain)
