"""Models for the DNS intelligence module.

:class:`DnsProfile` is the normalized representation of a domain's DNS
configuration consumed by the intelligence layer. All booleans and counts
are precomputed by the parser so rule evaluation never re-queries or
re-parses raw records.
"""

from pydantic import BaseModel, Field


class DnsProfile(BaseModel):
    """Normalized DNS posture for a domain."""

    domain: str
    ip_address: str | None = None
    ipv6_addresses: list[str] = Field(default_factory=list)
    resolves: bool = False

    # Record counts
    mx_count: int = 0
    ns_count: int = 0
    txt_count: int = 0
    caa_count: int = 0
    cname_count: int = 0
    record_counts: dict[str, int] = Field(default_factory=dict)

    # Records (display)
    mx_records: list[str] = Field(default_factory=list)
    ns_records: list[str] = Field(default_factory=list)
    txt_records: list[str] = Field(default_factory=list)
    caa_records: list[str] = Field(default_factory=list)
    dmarc_records: list[str] = Field(default_factory=list)

    # Email security
    spf: bool = False
    dmarc: bool = False
    dkim: bool = False
    dkim_selectors: list[str] = Field(default_factory=list)
    spf_status: str = "Missing"
    dmarc_status: str = "Missing"

    # DNS security
    dnssec: bool = False
    nameserver_duplicates: bool = False

    # Infrastructure
    ttl_min: int | None = None
    resolution_consistent: bool | None = None