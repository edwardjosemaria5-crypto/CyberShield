def get_popularity(domain: str) -> dict:
    """Assess domain popularity and trust tier based on TLD and authority characteristics."""
    target = domain.replace("https://", "").replace("http://", "").split("/")[0].split(":")[0].lower()
    tld = target.split(".")[-1] if "." in target else ""

    high_trust_tlds = {"gov", "edu", "mil"}
    standard_tlds = {"com", "org", "net", "io", "co", "uk", "ca", "de", "fr"}
    suspicious_tlds = {"zip", "mov", "top", "xyz", "click", "download", "racing", "work"}

    if tld in high_trust_tlds:
        tier = "High Trust"
        risk = "Low"
    elif tld in suspicious_tlds:
        tier = "High Risk TLD"
        risk = "High"
    elif tld in standard_tlds:
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
