from .scanner import scan_headers_module


def run_headers_check(domain: str):
    return scan_headers_module(domain)
