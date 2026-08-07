from .rules import HIGH_TRUST_TLDS, STANDARD_TLDS, SUSPICIOUS_TLDS


def get_popularity(domain: str) -> dict:
    """Assess domain popularity and trust tier based on TLD and authority characteristics."""
    target = domain.replace("https://", "").replace("http://", "").split("/")[0].split(":")[0].lower()
    tld = target.split(".")[-1] if "." in target else ""

    if tld in HIGH_TRUST_TLDS:
        tier = "High Trust"
        risk = "Low"
    elif tld in SUSPICIOUS_TLDS:
        tier = "High Risk TLD"
        risk = "High"
    elif tld in STANDARD_TLDS:
        tier = "Standard Commercial"
        risk = "Low"
    else:
        tier = "Generic TLD"
        risk = "Medium"

    return {
        "domain": target,
        "tld": tld,
        "trust_tier": tier,
        "tld_risk": risk,
    }