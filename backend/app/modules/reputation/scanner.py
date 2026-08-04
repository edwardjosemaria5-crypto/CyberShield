from app.modules.reputation.blacklist import get_blacklist_status
from app.modules.reputation.domain_age import get_domain_age
from app.modules.reputation.popularity import get_popularity


def scan_reputation_module(domain: str) -> dict:
    """Scan target domain for reputation signals including blacklist status, age, and TLD trust."""
    hostname = domain.replace("https://", "").replace("http://", "").split("/")[0].split(":")[0]

    age_data = get_domain_age(hostname)
    blacklist_data = get_blacklist_status(hostname)
    popularity_data = get_popularity(hostname)

    score = 100
    issues = []

    if blacklist_data["is_blacklisted"]:
        score -= 40
        issues.append(f"Domain listed on {len(blacklist_data['blacklisted_on'])} DNS blocklists.")

    if age_data["newly_registered"]:
        score -= 25
        issues.append(f"Domain is newly registered ({age_data['age_days']} days old).")

    if popularity_data["tld_risk"] == "High":
        score -= 15
        issues.append(f"Domain uses high-risk TLD (.{popularity_data['tld']}).")

    risk_level = "High" if score < 60 else "Medium" if score < 85 else "Low"

    return {
        "domain": hostname,
        "reputation_score": max(0, score),
        "risk_level": risk_level,
        "domain_age": age_data,
        "blacklist": blacklist_data,
        "popularity": popularity_data,
        "issues": issues,
    }
