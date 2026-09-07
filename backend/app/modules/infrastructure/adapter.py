"""Provider adapter boundary for infrastructure location intelligence.

Each external provider gets a concrete adapter behind this interface. The
``infrastructure`` scanner only ever sees the normalized
:class:`InfrastructureData` (or a typed :class:`UnavailableData`); vendor
response shapes never leak into the pipeline.

Design rules (mirrors the threat-intel adapter contract in
``app/modules/threatintel/adapters/base.py``):

- ``lookup`` must NEVER raise for transport- or payload problems; it
  returns :class:`UnavailableData` carrying the canonical reason instead.
  Programming errors may still raise (the scanner isolates those too).
- Provider responses are untrusted input; concrete adapters validate and
  normalize them, dropping unknown fields and leaving ``None`` as ``None``.
- An unavailable provider is a *missing data point*, never a verdict: the
  scanner maps every failure to an informational ``unavailable`` state with
  zero effect on scoring or findings.

Provider boundary security contract:

- ``lookup()`` receives a **validated public IP literal string only**.
- Callers must NEVER pass a raw hostname, original URL, userinfo,
  credentials, environment values, or the scan target string to this
  method.
- Future provider URLs must be fixed provider endpoints.  Provider URLs
  must NEVER be dynamically constructed using a scan-target hostname,
  domain, URL path, or userinfo.
- Concrete adapters must NOT log or expose API keys, secrets, or raw
  provider internals.
"""

from abc import ABC, abstractmethod

from pydantic import BaseModel, Field

from app.modules.infrastructure.rules import MAX_FIELD_LEN
from app.schemas.threat_intel import UnavailableReason


class InfrastructureData(BaseModel):
    """One normalized, provider-independent IP infrastructure lookup.

    All fields are nullable: a provider may legitimately not supply e.g.
    ``region`` or ``isp``; ``None`` stays ``None``. Normalization and
    validation happen inside the concrete adapter.

    Schema-level length bounds mirror the scanner's call-site ``_bound``
    truncation (defense-in-depth): even an adapter that forgets to truncate
    itself cannot persist or return an unbounded field.
    """

    ip: str | None = Field(default=None, max_length=MAX_FIELD_LEN)  # queried IP (echoed by the provider)
    asn: str | None = Field(default=None, max_length=MAX_FIELD_LEN)  # e.g. "AS15169"
    asn_organization: str | None = Field(default=None, max_length=MAX_FIELD_LEN)
    isp: str | None = Field(default=None, max_length=MAX_FIELD_LEN)
    hosting_provider: str | None = Field(default=None, max_length=MAX_FIELD_LEN)
    network: str | None = Field(default=None, max_length=MAX_FIELD_LEN)  # CIDR, e.g. "142.250.0.0/15"
    reverse_dns: str | None = Field(default=None, max_length=MAX_FIELD_LEN)  # PTR hostname
    country: str | None = Field(default=None, max_length=MAX_FIELD_LEN)
    country_code: str | None = Field(default=None, max_length=MAX_FIELD_LEN)  # ISO 3166-1 alpha-2
    region: str | None = Field(default=None, max_length=MAX_FIELD_LEN)  # state/province, provider-guaranteed only
    source: str | None = Field(default=None, max_length=MAX_FIELD_LEN)  # provider slug for provenance


class UnavailableData(BaseModel):
    """Typed failure returned by an adapter instead of raising.

    Carries the canonical ``UnavailableReason`` so the module can surface
    *why* the lookup failed without inventing severity (an unavailable
    provider is a missing data point, never a verdict).
    """

    provider: str = "unknown"
    reason: UnavailableReason = "network"
    #: Schema-level cap (mirrors the scanner's call-site ``_bound_detail``
    #: truncation) so a future adapter constructing ``UnavailableData``
    #: directly can never persist or return an unbounded detail blob.
    detail: str = Field(default="", max_length=80)


class InfrastructureAdapter(ABC):
    """Base contract every infrastructure provider adapter must implement.

    ``is_configurable`` defaults to ``False`` so that a new adapter must
    *consciously opt in* to configuration readiness — never inheriting
    a configurable state by accident.  The skeleton stays safe even if a
    future adapter forgets to override this property.
    """

    provider: str = "unknown"

    def __init__(self, timeout_seconds: float = 5.0) -> None:
        self.timeout_seconds = timeout_seconds

    @property
    def is_configurable(self) -> bool:
        """Whether the adapter has everything it needs to talk to its provider.

        Defaults to ``False`` so a new adapter must explicitly declare
        readiness (e.g. by overriding this to check for the presence of
        its API key / environment configuration).  A base adapter that
        forgets to override this property safely degrades to
        ``unavailable`` with ``missing_api_key``.
        """
        return False

    @abstractmethod
    def lookup(self, ip_address: str) -> InfrastructureData | UnavailableData:
        """Query the provider for one IP and return normalized data.

        Must receive a **validated public IP literal string** — never a
        raw hostname, URL, userinfo or credential.  Must never raise for
        transport- or payload problems; return :class:`UnavailableData`
        instead.  Programming errors may still raise (the scanner
        isolates them as ``bad_response``).
        """
        raise NotImplementedError

    def unavailable(
        self,
        reason: str = "network",
        detail: str = "",
    ) -> UnavailableData:
        """Build a typed unavailable result (never a verdict)."""
        return UnavailableData(
            provider=self.provider,
            reason=reason,
            detail=detail,
        )
