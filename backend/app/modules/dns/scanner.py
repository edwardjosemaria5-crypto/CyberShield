from app.modules.dns.resolver import resolve_domain


def scan_dns_module(domain: str) -> dict:
    """Scan domain DNS configuration, security records (SPF, DMARC), and name servers."""
    hostname = domain.replace("https://", "").replace("http://", "").split("/")[0].split(":")[0]
    records = resolve_domain(hostname)

    ip_address = records["A"][0] if records["A"] else None
    has_spf = records["spf_status"] == "Valid"
    has_dmarc = records["dmarc_status"] == "Valid"

    issues = []
    if not has_spf:
        issues.append("Missing SPF record - domain susceptible to email spoofing.")
    if not has_dmarc:
        issues.append("Missing DMARC policy - domain lacks email authentication policy.")
    if not records["MX"]:
        issues.append("No MX records configured for target domain.")

    security_score = 100 - (20 if not has_spf else 0) - (20 if not has_dmarc else 0)

    return {
        "domain": hostname,
        "ip_address": ip_address,
        "records": records,
        "security_score": max(0, security_score),
        "spf_status": records["spf_status"],
        "dmarc_status": records["dmarc_status"],
        "issues": issues,
    }
