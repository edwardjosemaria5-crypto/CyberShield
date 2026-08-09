"""Normalized external threat-intelligence result contract.

Providers (Google Safe Browsing, VirusTotal, Urlhaus, ...) return their own
response formats. Adapters translate those into this canonical shape so the
rest of CyberShield never depends on any single vendor's API.

The contract deliberately separates *provider availability* from *verdict*:

- ``status == "unavailable"`` means we learned NOTHING reliable. That is
  NOT a malicious verdict and must never raise the risk score.
- ``status == "available"`` means the provider answered and the verdict
  fields below carry its (untrusted-but-validated) findings.
"""

from datetime import datetime, timezone
from typing import Literal

from pydantic import BaseModel, Field

ProviderStatus = Literal["available", "unavailable"]

#: Reason codes for an unavailable provider; safe to show to users.
UnavailableReason = Literal[
    "missing_api_key",
    "invalid_target",
    "timeout",
    "network",
    "rate_limited",
    "unauthorized",
    "bad_response",
    "server_error",
    "no_analysis",
    "unknown",
]

#: Canonical threat categories propagated beyond a provider's own labels.
ThreatCategory = Literal[
    "malware",
    "social-engineering",
    "unwanted-software",
    "phishing",
    "malicious-download",
    "exploit",
    "unknown",
]


class ThreatIntelSignals(BaseModel):
    """One normalized, provider-independent threat lookup result."""

    provider: str
    status: ProviderStatus = "unavailable"
    reason: UnavailableReason = "network"
    malicious: bool = False
    suspicious: bool = False
    detections: int = Field(default=0, ge=0)
    categories: list[ThreatCategory] = Field(default_factory=list)
    confidence: int = Field(default=0, ge=0, le=100)
    evidence: list[str] = Field(default_factory=list, description="Human-readable grounds for the signal.")
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())