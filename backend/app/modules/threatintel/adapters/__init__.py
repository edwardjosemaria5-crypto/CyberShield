"""External threat-intelligence provider adapters.

Adapters convert vendor-specific APIs into the normalized
:class:`~app.schemas.threat_intel.ThreatIntelSignals` contract. Adding a new
provider means adding a new concrete :class:`ThreatIntelAdapter` here and
registering it in :func:`build_adapters`.

The correlation layer consumes signals, never adapters — provider-specific
response shapes never leak beyond this package.
"""

from app.modules.threatintel.adapters.base import ThreatIntelAdapter
from app.modules.threatintel.adapters.google_safe_browsing import GoogleSafeBrowsingAdapter
from app.modules.threatintel.adapters.virustotal import VirusTotalAdapter

__all__ = ["ThreatIntelAdapter", "GoogleSafeBrowsingAdapter", "VirusTotalAdapter"]


def build_adapters(
    google_safe_browsing_api_key: str | None = None,
    google_safe_browsing_timeout: float = 5.0,
    virus_total_api_key: str | None = None,
    virus_total_timeout: float = 8.0,
) -> list[ThreatIntelAdapter]:
    """Instantiate every configured provider adapter.

    An adapter is included only when the provider is configured (API key
    present). Providers without configuration are skipped, keeping the
    threat-intel stage a no-op when no external intelligence is available.
    """
    adapters: list[ThreatIntelAdapter] = []
    if google_safe_browsing_api_key:
        adapters.append(
            GoogleSafeBrowsingAdapter(
                api_key=google_safe_browsing_api_key,
                timeout_seconds=google_safe_browsing_timeout,
            )
        )
    if virus_total_api_key:
        adapters.append(
            VirusTotalAdapter(
                api_key=virus_total_api_key,
                timeout_seconds=virus_total_timeout,
            )
        )
    return adapters