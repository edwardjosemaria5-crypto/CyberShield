"""Data model for the infrastructure intelligence module.

:class:`InfrastructureProfile` is purely informational hosting/location
context for one resolved IP of the scanned domain. It is explicitly
excluded from risk scoring (the module has no entry in ``MODULE_WEIGHTS``),
so its values can never move the Trust Score, verdict, module penalties or
finding severities.
"""

from typing import Literal

from pydantic import BaseModel, Field

from app.schemas.threat_intel import UnavailableReason
from app.utils.time import utc_now

InfrastructureStatus = Literal["available", "unavailable"]


class InfrastructureProfile(BaseModel):
    """Informational hosting/location context for a resolved IP.

    Approximate by nature: IP geolocation locates the network endpoint,
    not a person. This profile is display context only; it is excluded
    from risk scoring by construction (no weight in ``MODULE_WEIGHTS``).
    """

    domain: str
    ip_address: str | None = None           # first resolved IP queried
    asn: str | None = None
    asn_organization: str | None = None
    isp: str | None = None
    hosting_provider: str | None = None
    network: str | None = None              # CIDR
    reverse_dns: str | None = None
    country: str | None = None
    country_code: str | None = None
    region: str | None = None
    source: str | None = None               # provider slug
    status: InfrastructureStatus = "unavailable"
    reason: UnavailableReason = "network"   # reuse threatintel reason codes
    timestamp: str = Field(default_factory=utc_now, description="UTC ISO-8601")
