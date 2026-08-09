import ipaddress
from urllib.parse import urlparse

from app.schemas.finding import Finding
from app.schemas.module_result import ModuleResult, score_to_status
from app.utils.urls import ensure_scheme
from .rules import (
    IP_ADDRESS_PENALTY,
    MANY_SUBDOMAINS_PENALTY,
    MAX_SUBDOMAINS,
    MAX_URL_LENGTH,
    NO_HTTPS_PENALTY,
    NON_STANDARD_CHARS_PENALTY,
    PUNYCODE_PENALTY,
    SUSPICIOUS_KEYWORD_PENALTY,
    SUSPICIOUS_KEYWORDS,
    URL_LENGTH_PENALTY,
)


class URLAnalyzer:
    """Structural URL analyzer.

    Responsibilities are intentionally narrow and match the platform spec:
    1. Normalize the URL
    2. Validate the URL
    3. Extract the domain
    4. Detect suspicious URL structure

    This module never computes the final trust score; it only reports its own
    module-level score to the ScanManager / risk engine.
    """

    def analyze(self, url: str) -> ModuleResult:
        original_url = url.strip()
        normalized_url = ensure_scheme(original_url)
        parsed = urlparse(normalized_url)
        hostname = parsed.hostname or ""
        domain = hostname
        uses_https = parsed.scheme == "https"
        is_ip_address = False

        findings: list[Finding] = []
        score = 100
        is_valid = bool(hostname and parsed.scheme in {"http", "https"} and " " not in original_url)

        if not is_valid:
            score = 0
            findings.append(
                Finding(
                    title="Invalid URL",
                    severity="critical",
                    description="The URL is invalid or missing a valid hostname.",
                    recommendation="Submit a valid HTTP or HTTPS URL with a proper domain or IP address.",
                )
            )
            # Confidence must be 0 for an invalid target: the analyzer could
            # not extract any evidence, so the aggregate assessment must not
            # present the input as confidently (maliciously) classified.
            return ModuleResult(
                module="url_analysis",
                status="critical" if score < 70 else "warning",
                score=score,
                confidence=0,
                findings=findings,
                details={
                    "original_url": original_url,
                    "normalized_url": normalized_url,
                    "domain": domain,
                    "is_valid": False,
                    "uses_https": uses_https,
                    "is_ip_address": False,
                    "url_length": len(normalized_url),
                    "subdomain_count": 0,
                },
            )

        try:
            ipaddress.ip_address(hostname)
            is_ip_address = True
        except ValueError:
            is_ip_address = False

        if is_ip_address:
            score -= IP_ADDRESS_PENALTY
            findings.append(
                Finding(
                    title="IP address in URL",
                    severity="medium",
                    description="The URL uses an IP address instead of a domain name.",
                    recommendation="Use a registered domain name instead of an IP address where possible.",
                )
            )

        if not uses_https:
            score -= NO_HTTPS_PENALTY
            findings.append(
                Finding(
                    title="Missing HTTPS",
                    severity="medium",
                    description="The website is not using HTTPS.",
                    recommendation="Switch the website to HTTPS to protect data in transit.",
                )
            )

        subdomain_count = max(0, len(hostname.split(".")) - 2)
        if len(normalized_url) > MAX_URL_LENGTH:
            score -= URL_LENGTH_PENALTY
            findings.append(
                Finding(
                    title="Unusually long URL",
                    severity="low",
                    description="The URL is unusually long.",
                    recommendation="Shorten the URL if possible to reduce phishing risk.",
                )
            )

        if "xn--" in hostname.lower():
            score -= PUNYCODE_PENALTY
            findings.append(
                Finding(
                    title="Punycode domain",
                    severity="medium",
                    description="The domain uses punycode, which can be used for homograph attacks.",
                    recommendation="Verify the domain carefully and avoid suspicious punycode domains.",
                )
            )

        if "_" in hostname or " " in hostname:
            score -= NON_STANDARD_CHARS_PENALTY
            findings.append(
                Finding(
                    title="Non-standard domain characters",
                    severity="low",
                    description="The domain contains non-standard characters.",
                    recommendation="Use a valid hostname without underscores or whitespace.",
                )
            )

        path_and_query = f"{parsed.path} {parsed.query}".lower()
        if any(keyword in path_and_query for keyword in SUSPICIOUS_KEYWORDS):
            score -= SUSPICIOUS_KEYWORD_PENALTY
            findings.append(
                Finding(
                    title="Suspicious URL keywords",
                    severity="medium",
                    description="The URL path or query contains suspicious keywords.",
                    recommendation="Avoid using suspicious terms in the URL path or query parameters.",
                )
            )

        if subdomain_count > MAX_SUBDOMAINS:
            score -= MANY_SUBDOMAINS_PENALTY
            findings.append(
                Finding(
                    title="Excessive subdomains",
                    severity="low",
                    description="The domain contains many subdomains.",
                    recommendation="Reduce subdomain depth to avoid suspicious or confusing URLs.",
                )
            )

        score = max(0, min(100, score))

        return ModuleResult(
            module="url_analysis",
            status=score_to_status(score),
            score=score,
            confidence=100,
            findings=findings,
            details={
                "original_url": original_url,
                "normalized_url": normalized_url,
                "domain": domain,
                "is_valid": True,
                "uses_https": uses_https,
                "is_ip_address": is_ip_address,
                "url_length": len(normalized_url),
                "subdomain_count": subdomain_count,
            },
        )


def scan_url_analysis_module(url: str) -> ModuleResult:
    return URLAnalyzer().analyze(url)