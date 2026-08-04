import datetime
import whois


def get_domain_age(domain: str) -> dict:
    """Determine domain registration age and risk factor."""
    try:
        w = whois.whois(domain)
        creation_date = w.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]

        if creation_date:
            now = datetime.datetime.utcnow()
            age_days = (now - creation_date).days
            age_years = round(age_days / 365.25, 1)

            risk = "High" if age_days < 30 else "Medium" if age_days < 180 else "Low"
            return {
                "age_days": age_days,
                "age_years": age_years,
                "created_at": str(creation_date),
                "risk": risk,
                "newly_registered": age_days < 30,
            }
    except Exception:
        pass

    return {
        "age_days": None,
        "age_years": None,
        "created_at": "Unknown",
        "risk": "Medium",
        "newly_registered": False,
    }
