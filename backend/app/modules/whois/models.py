"""Pydantic models for the WHOIS intelligence module.

:class:`WhoisProfile` is the normalized, registrar-agnostic representation of
a WHOIS record. Every provider-specific quirk is absorbed by the parser so
downstream consumers (intelligence rules, service, frontend) only ever see
this consistent shape.
"""

from pydantic import BaseModel, Field


class WhoisProfile(BaseModel):
    """Normalized WHOIS registration profile for a domain.

    Dates are stored as ISO-8601 strings; the derived day-based metrics
    (``domain_age_days``, ``expires_in_days``) are computed by the parser so
    the intelligence layer never parses raw dates itself. Missing or
    malformed values degrade to ``None``/empty lists, never exceptions.
    """

    domain: str
    registrar: str | None = None
    creation_date: str | None = None
    updated_date: str | None = None
    expiration_date: str | None = None
    domain_age_days: int | None = None
    expires_in_days: int | None = None
    organization: str | None = None
    country: str | None = None
    dnssec: str | None = None
    registrar_url: str | None = None
    name_servers: list[str] = Field(default_factory=list)
    name_server_count: int = 0
