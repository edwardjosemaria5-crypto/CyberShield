"""Risk-engine facade used by application services."""

from .scorer import score_scan


def calculate_scan_risk(headers_result: dict, dns_result: dict, whois_result: dict) -> dict:
    score, issues = score_scan(headers_result, dns_result, whois_result)
    overall_risk = "Low" if score >= 80 else "Medium" if score >= 60 else "High"
    return {"security_score": score, "overall_risk": overall_risk, "issues": issues}


def calculate_risk_score(*args, **kwargs):
    """Reserved compatibility entry point for future risk-engine consumers."""
    return 0
