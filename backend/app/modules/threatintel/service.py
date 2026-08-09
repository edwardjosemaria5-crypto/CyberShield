from app.core.config import (
    GOOGLE_SAFE_BROWSING_API_KEY,
    GOOGLE_SAFE_BROWSING_TIMEOUT_SECONDS,
    THREAT_PROVIDER_ENABLED,
    VIRUS_TOTAL_API_KEY,
    VIRUS_TOTAL_TIMEOUT_SECONDS,
)
from app.modules.threatintel.adapters import build_adapters
from app.modules.threatintel.scanner import scan_threatintel_module
from app.schemas.module_result import ModuleResult


def run_threatintel_check(domain: str) -> ModuleResult:
    adapters = (
        build_adapters(
            google_safe_browsing_api_key=GOOGLE_SAFE_BROWSING_API_KEY,
            google_safe_browsing_timeout=GOOGLE_SAFE_BROWSING_TIMEOUT_SECONDS,
            virus_total_api_key=VIRUS_TOTAL_API_KEY,
            virus_total_timeout=VIRUS_TOTAL_TIMEOUT_SECONDS,
        )
        if THREAT_PROVIDER_ENABLED
        else []
    )
    return scan_threatintel_module(domain, adapters=adapters)