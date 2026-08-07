from .rules import KNOWN_MALICIOUS_DOMAINS


def get_blacklist_data(domain: str) -> dict:
    """Retrieve threat intelligence feed match status for target domain."""
    target = domain.replace("https://", "").replace("http://", "").split("/")[0].split(":")[0].lower()

    is_flagged = target in KNOWN_MALICIOUS_DOMAINS

    return {
        "domain": target,
        "is_flagged": is_flagged,
        "threat_feed_status": "Flagged Malicious" if is_flagged else "Clean",
    }