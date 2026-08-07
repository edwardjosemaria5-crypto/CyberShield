"""Module registry: the single source of truth for scan pipeline scanners.

The ScanManager iterates over :data:`MODULE_REGISTRY` instead of hardcoding
execution order. Adding a new scanner here (or to the list of scanners) is
the only change required to include it in every scan; the ScanManager and
risk engine remain untouched.
"""

from app.modules.base import TARGET_DOMAIN, TARGET_URL, BaseModule
from app.modules.blacklist.service import run_blacklist_check
from app.modules.brand_detection.service import run_brand_detection_check
from app.modules.dns.service import run_dns_check
from app.modules.headers.service import run_headers_check
from app.modules.phishing.service import run_phishing_check
from app.modules.reputation.service import run_reputation_check
from app.modules.ssl.service import run_ssl_check
from app.modules.threatintel.service import run_threatintel_check
from app.modules.typosquatting.service import run_typosquatting_check
from app.modules.url_analysis.service import run_url_analysis_check
from app.modules.whois.service import run_whois_check
from app.schemas.module_result import ModuleResult


class URLAnalysisScanner(BaseModule):
    """Structural analysis of the target URL (scheme, host, path)."""

    def __init__(self) -> None:
        super().__init__(
            name="url_analysis",
            description="Structural analysis of the target URL",
            target_kind=TARGET_URL,
        )

    def run(self, target: str) -> ModuleResult:
        return run_url_analysis_check(target)


class ReputationScanner(BaseModule):
    """Domain reputation assessment based on heuristics and popularity."""

    def __init__(self) -> None:
        super().__init__(
            name="reputation",
            description="Domain reputation assessment",
            target_kind=TARGET_DOMAIN,
        )

    def run(self, target: str) -> ModuleResult:
        return run_reputation_check(target)


class WHOISScanner(BaseModule):
    """Registrar, registration and expiry metadata via WHOIS."""

    def __init__(self) -> None:
        super().__init__(
            name="whois",
            description="WHOIS registration metadata",
            target_kind=TARGET_DOMAIN,
        )

    def run(self, target: str) -> ModuleResult:
        return run_whois_check(target)


class DNSScanner(BaseModule):
    """DNS record resolution and mail/SPF/DMARC posture."""

    def __init__(self) -> None:
        super().__init__(
            name="dns",
            description="DNS record resolution analysis",
            target_kind=TARGET_DOMAIN,
        )

    def run(self, target: str) -> ModuleResult:
        return run_dns_check(target)


class SSLScanner(BaseModule):
    """TLS certificate validity, chain, and cipher configuration."""

    def __init__(self) -> None:
        super().__init__(
            name="ssl",
            description="SSL/TLS certificate inspection",
            target_kind=TARGET_DOMAIN,
        )

    def run(self, target: str) -> ModuleResult:
        return run_ssl_check(target)


class HeaderScanner(BaseModule):
    """HTTP security-header posture and grading."""

    def __init__(self) -> None:
        super().__init__(
            name="headers",
            description="HTTP security headers assessment",
            target_kind=TARGET_DOMAIN,
        )

    def run(self, target: str) -> ModuleResult:
        return run_headers_check(target)


class TyposquattingScanner(BaseModule):
    """Brand-similarity analysis: does the target imitate a known brand?"""

    def __init__(self) -> None:
        super().__init__(
            name="typosquatting",
            description="Brand-similarity typosquatting detection",
            target_kind=TARGET_DOMAIN,
        )

    def run(self, target: str) -> ModuleResult:
        return run_typosquatting_check(target)


class BrandDetectionScanner(BaseModule):
    """Brand keyword and impersonation-combination detection."""

    def __init__(self) -> None:
        super().__init__(
            name="brand_detection",
            description="Brand impersonation and keyword-combination detection",
            target_kind=TARGET_DOMAIN,
        )

    def run(self, target: str) -> ModuleResult:
        return run_brand_detection_check(target)


class ThreatIntelScanner(BaseModule):
    """Internal threat-intel indicators (phishing, malware, blacklists)."""

    def __init__(self) -> None:
        super().__init__(
            name="threatintel",
            description="Threat intelligence indicator lookup",
            target_kind=TARGET_DOMAIN,
        )

    def run(self, target: str) -> ModuleResult:
        return run_threatintel_check(target)


class BlacklistScanner(BaseModule):
    """Local blacklist and reputation feed lookup."""

    def __init__(self) -> None:
        super().__init__(
            name="blacklist",
            description="Blacklist membership check",
            target_kind=TARGET_DOMAIN,
        )

    def run(self, target: str) -> ModuleResult:
        return run_blacklist_check(target)


class PhishingScanner(BaseModule):
    """Phishing heuristics applied to the target hostname."""

    def __init__(self) -> None:
        super().__init__(
            name="phishing",
            description="Phishing heuristic detection",
            target_kind=TARGET_DOMAIN,
        )

    def run(self, target: str) -> ModuleResult:
        return run_phishing_check(target)


#: Canonical pipeline order. URL scanners run first (sequential stage),
#: domain scanners follow (concurrent stage) and preserve registry order.
MODULE_REGISTRY: list[BaseModule] = [
    URLAnalysisScanner(),
    ReputationScanner(),
    WHOISScanner(),
    DNSScanner(),
    SSLScanner(),
    HeaderScanner(),
    TyposquattingScanner(),
    BrandDetectionScanner(),
    ThreatIntelScanner(),
    BlacklistScanner(),
    PhishingScanner(),
]


def get_module_registry() -> list[BaseModule]:
    """Return the canonical scanner list consumed by the ScanManager.

    Returns a new list over the shared scanner instances so callers can
    re-order or filter without mutating the global registry.
    """
    return list(MODULE_REGISTRY)
