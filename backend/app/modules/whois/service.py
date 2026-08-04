from .scanner import scan_whois_module


def run_whois_check(domain: str):
    return scan_whois_module(domain)
