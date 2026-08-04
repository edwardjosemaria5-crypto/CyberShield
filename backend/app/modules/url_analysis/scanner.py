import ipaddress
from urllib.parse import urlparse

from app.utils.urls import ensure_scheme
from .models import URLAnalysisResult


class URLAnalyzer:
    SUSPICIOUS_KEYWORDS = {
        "login",
        "secure",
        "account",
        "verify",
        "update",
        "bank",
        "paypal",
        "confirm",
        "signin",
    }

    def analyze(self, url: str) -> URLAnalysisResult:
        original_url = url.strip()
        normalized_url = ensure_scheme(original_url)
        parsed = urlparse(normalized_url)
        hostname = parsed.hostname or ""
        domain = hostname

        findings: list[str] = []
        recommendations: list[str] = []
        risk_score = 100
        uses_https = parsed.scheme == "https"
        is_valid = bool(hostname and parsed.scheme in {"http", "https"} and " " not in original_url)
        is_ip_address = False

        if not is_valid:
            findings.append("The URL is invalid or missing a valid hostname.")
            recommendations.append("Submit a valid HTTP or HTTPS URL with a proper domain or IP address.")
            return URLAnalysisResult(
                original_url=original_url,
                normalized_url=normalized_url,
                domain=domain,
                is_valid=False,
                uses_https=uses_https,
                is_ip_address=False,
                url_length=len(normalized_url),
                subdomain_count=0,
                risk_score=0,
                findings=findings,
                recommendations=recommendations,
            )

        try:
            ipaddress.ip_address(hostname)
            is_ip_address = True
        except ValueError:
            is_ip_address = False

        if is_ip_address:
            risk_score -= 25
            findings.append("The URL uses an IP address instead of a domain name.")
            recommendations.append("Use a registered domain name instead of an IP address where possible.")

        if not uses_https:
            risk_score -= 20
            findings.append("The website is not using HTTPS.")
            recommendations.append("Switch the website to HTTPS to protect data in transit.")

        if len(normalized_url) > 100:
            risk_score -= 10
            findings.append("The URL is unusually long.")
            recommendations.append("Shorten the URL if possible to reduce phishing risk.")

        if "xn--" in hostname.lower():
            risk_score -= 10
            findings.append("The domain uses punycode, which can be used for homograph attacks.")
            recommendations.append("Verify the domain carefully and avoid suspicious punycode domains.")

        if "_" in hostname or " " in hostname:
            risk_score -= 5
            findings.append("The domain contains non-standard characters.")
            recommendations.append("Use a valid hostname without underscores or whitespace.")

        path_and_query = f"{parsed.path} {parsed.query}".lower()
        if any(keyword in path_and_query for keyword in self.SUSPICIOUS_KEYWORDS):
            risk_score -= 10
            findings.append("The URL path or query contains suspicious keywords.")
            recommendations.append("Avoid using suspicious terms in the URL path or query parameters.")

        host_parts = hostname.split(".")
        subdomain_count = max(0, len(host_parts) - 2)
        if subdomain_count > 3:
            risk_score -= 10
            findings.append("The domain contains many subdomains.")
            recommendations.append("Reduce subdomain depth to avoid suspicious or confusing URLs.")

        return URLAnalysisResult(
            original_url=original_url,
            normalized_url=normalized_url,
            domain=domain,
            is_valid=True,
            uses_https=uses_https,
            is_ip_address=is_ip_address,
            url_length=len(normalized_url),
            subdomain_count=subdomain_count,
            risk_score=max(0, min(risk_score, 100)),
            findings=findings,
            recommendations=recommendations,
        )


def scan_url_analysis_module(url: str) -> URLAnalysisResult:
    return URLAnalyzer().analyze(url)
