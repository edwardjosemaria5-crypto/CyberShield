"""Provider adapter contract for external threat intelligence.

Each external provider gets a concrete adapter behind this interface. The
``threatintel`` scanner (and therefore the risk engine) only ever sees
:class:`~app.schemas.threat_intel.ThreatIntelSignals`; provider-specific
response shapes never leak into the pipeline.

Provider failures are converted into an *unavailable* signal. An
unavailable provider is NOT a negative verdict: the caller must never turn
provider absence into suspiciousness.
"""

from abc import ABC, abstractmethod

from app.schemas.threat_intel import ThreatIntelSignals


class ThreatIntelAdapter(ABC):
    """Base contract every threat-intel provider adapter must implement."""

    provider: str = "unknown"

    def __init__(self, api_key: str | None = None, timeout_seconds: float = 5.0) -> None:
        self.api_key = api_key
        self.timeout_seconds = timeout_seconds

    @property
    def is_configured(self) -> bool:
        """True when the adapter can actually talk to its provider."""
        return bool(self.api_key)

    @abstractmethod
    def lookup(self, target: str) -> ThreatIntelSignals:
        """Query the provider for one domain / URL and return normalized signals.

        Must never raise for network- or provider-facing problems; return an
        unavailable signal instead. Programming errors may still raise.
        """
        raise NotImplementedError

    def unavailable(
        self,
        reason: str = "network",
        detail: str = "",
    ) -> ThreatIntelSignals:
        """Build an unavailable signals payload (never a verdict)."""
        return ThreatIntelSignals(
            provider=self.provider,
            status="unavailable",
            reason=reason,
            evidence=[detail] if detail else [],
        )