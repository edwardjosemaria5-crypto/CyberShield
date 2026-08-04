"""Pure score calculation helpers."""

from . import weights


def score_scan(headers_result: dict, dns_result: dict, whois_result: dict) -> tuple[int, list[str]]:
    score = 100
    issues = []
    if "error" in headers_result:
        score -= weights.HEADER_ERROR_PENALTY
        issues.append("headers")
    else:
        missing_headers = headers_result.get("summary", {}).get("missing_headers", 0)
        score -= min(weights.MAX_MISSING_HEADER_PENALTY, missing_headers * weights.MISSING_HEADER_PENALTY)
    if "error" in dns_result:
        score -= weights.DNS_ERROR_PENALTY
        issues.append("dns")
    if "error" in whois_result:
        score -= weights.WHOIS_ERROR_PENALTY
        issues.append("whois")
    return max(0, min(100, score)), issues
