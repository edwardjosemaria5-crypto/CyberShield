from app.modules.ssl.scanner import scan_ssl_module


def run_ssl_check(domain: str):
    return scan_ssl_module(domain)
