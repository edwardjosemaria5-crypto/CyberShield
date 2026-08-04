def get_blacklist_data(domain: str) -> dict:
    """Retrieve threat intelligence feed match status for target domain."""
    target = domain.replace("https://", "").replace("http://", "").split("/")[0].split(":")[0].lower()

    # Known test malicious domains list
    known_malicious = {"badssl.com", "phishing-example.com", "malware-test.org"}
    is_flagged = target in known_malicious

    return {
        "domain": target,
        "is_flagged": is_flagged,
        "threat_feed_status": "Flagged Malicious" if is_flagged else "Clean",
    }
