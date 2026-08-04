from app.modules.threatintel.blacklist import get_blacklist_data
from app.modules.threatintel.malware import get_malware_data
from app.modules.threatintel.phishing import get_phishing_data


def scan_threatintel_module(domain: str) -> dict:
    """Scan target domain across aggregated Threat Intelligence feeds (Phishing, Malware, Blacklists)."""
    hostname = domain.replace("https://", "").replace("http://", "").split("/")[0].split(":")[0]

    phishing_data = get_phishing_data(hostname)
    malware_data = get_malware_data(hostname)
    blacklist_data = get_blacklist_data(hostname)

    threat_score = 100
    threats_detected = []

    if phishing_data["is_phishing_suspect"]:
        threat_score -= 30
        threats_detected.append(f"Phishing keyword pattern detected ({', '.join(phishing_data['detected_keywords'])}).")

    if malware_data["is_malware_suspect"]:
        threat_score -= 40
        threats_detected.append(f"Malware host pattern flagged ({malware_data['suspicious_pattern']}).")

    if blacklist_data["is_flagged"]:
        threat_score -= 50
        threats_detected.append("Domain listed on active global threat intelligence feed.")

    threat_level = "High" if threat_score < 60 else "Medium" if threat_score < 90 else "Low"

    return {
        "domain": hostname,
        "threat_intel_score": max(0, threat_score),
        "threat_level": threat_level,
        "phishing_analysis": phishing_data,
        "malware_analysis": malware_data,
        "threat_feed_status": blacklist_data,
        "threats_detected": threats_detected,
    }
