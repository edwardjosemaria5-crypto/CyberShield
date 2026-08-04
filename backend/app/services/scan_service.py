from app.modules.dns.service import run_dns_check
from app.modules.headers.service import run_headers_check
from app.modules.whois.service import run_whois_check
from app.risk_engine.engine import calculate_scan_risk


def run_scan(domain: str):
    headers_result = run_headers_check(domain)
    dns_result = run_dns_check(domain)
    whois_result = run_whois_check(domain)
    risk = calculate_scan_risk(headers_result, dns_result, whois_result)

    return {
        "target": domain,
        "security_score": risk["security_score"],
        "overall_risk": risk["overall_risk"],
        "issues": risk["issues"],
        "modules": {
            "headers": headers_result,
            "dns": dns_result,
            "whois": whois_result,
        },
    }
