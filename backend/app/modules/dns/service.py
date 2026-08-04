from .scanner import scan_dns_module


def run_dns_check(domain: str):
    return scan_dns_module(domain)
