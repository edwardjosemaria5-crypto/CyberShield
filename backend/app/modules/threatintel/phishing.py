SUSPICIOUS_KEYWORDS = [
    "login", "verify", "secure", "account", "banking", "update",
    "support", "paypal", "apple", "microsoft", "google", "meta",
    "password", "credential", "auth", "signin", "wallet", "crypto",
]


def get_phishing_data(domain: str) -> dict:
    """Analyze domain structure and keyword patterns for phishing indicators."""
    target = domain.replace("https://", "").replace("http://", "").split("/")[0].split(":")[0].lower()

    detected_keywords = [kw for kw in SUSPICIOUS_KEYWORDS if kw in target]
    subdomain_count = max(0, target.count(".") - 1)
    has_hyphens = target.count("-") > 1

    is_suspicious = len(detected_keywords) > 0 or subdomain_count > 2 or has_hyphens
    risk = "High" if len(detected_keywords) > 1 or (subdomain_count > 2 and len(detected_keywords) >= 1) else "Medium" if is_suspicious else "Low"

    return {
        "domain": target,
        "is_phishing_suspect": is_suspicious,
        "phishing_risk": risk,
        "detected_keywords": detected_keywords,
        "subdomain_depth": subdomain_count,
        "hyphen_count": target.count("-"),
    }