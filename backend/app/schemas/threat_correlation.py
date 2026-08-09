"""Canonical multi-provider threat-intelligence correlation contract.

One provider returns one :class:`~app.schemas.threat_intel.ThreatIntelSignals`.
Several providers can return several, possibly disagreeing, signals. The
correlation engine reduces that collection into a single
:class:`CorrelationResult` that answers, provider-independently:

- how many providers answered, and how many of each verdict
- whether the providers agree, partially agree, or explicitly conflict
- one aggregate malicious/suspicious confidence
- the deduplicated category and evidence union
- the original signals untouched (evidence provenance)

The contract lives *next to* ``ThreatIntelSignals`` and intentionally does
not duplicate it: ``signals`` IS the per-provider layer. Consumers that need
raw provenance read ``signals``; consumers that need the consolidated view
read the summary fields.

Invariants enforced by this schema:

- ``malicious_count``, ``suspicious_count`` and ``clean_count`` are disjoint
  and sum to at most ``available_count``.
- A signal with ``status != "available"`` never counts as a verdict and can
  never raise ``malicious_count`` -- provider absence is not evidence.
- ``conflict`` is true exactly when at least one provider is malicious and
  at least one other available provider reported clean.
"""

from typing import Literal

from pydantic import BaseModel, Field

from app.schemas.threat_intel import ThreatCategory, ThreatIntelSignals

Agreement = Literal["consistent", "partial", "conflict", "none"]

#: Final consolidated classification: ``"unavailable"`` when no provider
#: answered, ``"conflict"`` when malicious and clean verdicts co-exist.
Consensus = Literal["malicious", "suspicious", "clean", "conflict", "unavailable"]


class CorrelationResult(BaseModel):
    """Provider-independent reconciliation of a list of threat-intel signals."""

    provider_count: int = Field(default=0, ge=0)
    available_count: int = Field(default=0, ge=0)
    unavailable_count: int = Field(default=0, ge=0)
    malicious_count: int = Field(default=0, ge=0)
    suspicious_count: int = Field(default=0, ge=0)
    clean_count: int = Field(default=0, ge=0)

    #: Agreement: "consistent" means every available provider agreed;
    #: "partial" means available providers differ without hard conflict;
    #: "conflict" means malicious and clean verdicts both occurred;
    #: "none" when no provider produced a verdict (nothing was learned).
    agreement: Agreement = "none"

    #: Consolidated verdict direction; "conflict" is a verdict direction
    #: of its own (see Consensus).
    consensus: Consensus = "unavailable"

    #: True exactly when at least one malicious signal AND one clean signal
    #: were returned by available providers.
    conflict: bool = False

    #: Confidence (0-100) attributed to the malicious verdict. 0 when no
    #: provider flagged malicious, or when flagged without any confidence.
    malicious_confidence: int = Field(default=0, ge=0, le=100)
    #: Confidence (0-100) attributed to the suspicious verdict.
    suspicious_confidence: int = Field(default=0, ge=0, le=100)

    #: Canonical category union, deduplicated, deterministic order.
    categories: list[ThreatCategory] = Field(default_factory=list)
    #: Deduplicated provider evidence strings (provenance kept per signal).
    evidence: list[str] = Field(default_factory=list)

    #: Original provider signals, untouched, one per provider (deduplicated
    #: by provider name, first occurrence wins).
    signals: list[ThreatIntelSignals] = Field(default_factory=list)