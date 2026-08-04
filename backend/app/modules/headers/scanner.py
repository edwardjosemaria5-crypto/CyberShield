import requests


def scan_headers_module(domain: str):
    """Scan a website for the existing set of HTTP security headers."""
    url = domain if domain.startswith(("http://", "https://")) else f"https://{domain}"
    try:
        response = requests.get(url, timeout=10)
    except requests.RequestException as exc:
        return {"error": str(exc)}

    header_definitions = {
        "Content-Security-Policy": ("High", "Implement a Content-Security-Policy header to reduce XSS attacks."),
        "Strict-Transport-Security": ("High", "Enable HSTS to force browsers to use HTTPS."),
        "X-Frame-Options": ("Medium", "Set X-Frame-Options to DENY or SAMEORIGIN."),
        "X-Content-Type-Options": ("Medium", "Set X-Content-Type-Options to nosniff."),
        "Referrer-Policy": ("Low", "Configure a Referrer-Policy to protect user privacy."),
        "Permissions-Policy": ("Low", "Restrict browser features using a Permissions-Policy."),
    }
    weights = {
        "Content-Security-Policy": 25, "Strict-Transport-Security": 20,
        "X-Frame-Options": 15, "X-Content-Type-Options": 15,
        "Referrer-Policy": 15, "Permissions-Policy": 10,
    }
    results = {}
    for header, (risk, recommendation) in header_definitions.items():
        value = response.headers.get(header)
        results[header] = (
            {"status": "Present", "risk": "None", "value": value}
            if value else {"status": "Missing", "risk": risk, "recommendation": recommendation}
        )

    score = sum(weights[header] for header, result in results.items() if result["status"] == "Present")
    grade = "A+" if score >= 95 else "A" if score >= 90 else "B" if score >= 80 else "C" if score >= 70 else "D" if score >= 60 else "F"
    overall_risk = "Low" if score >= 90 else "Medium" if score >= 70 else "High"
    present_headers = sum(result["status"] == "Present" for result in results.values())
    return {
        "url": response.url, "security_score": score, "grade": grade,
        "overall_risk": overall_risk,
        "summary": {"present_headers": present_headers, "missing_headers": len(results) - present_headers},
        "security_headers": results,
    }
