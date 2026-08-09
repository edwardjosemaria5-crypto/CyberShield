"""Provider-independent threat-intelligence correlation engine.

Consumes the canonical :class:`~app.schemas.threat_intel.ThreatIntelSignals`
contract and reduces a collection of signals into ONE
:class:`~app.schemas.threat_correlation.CorrelationResult`.

This module MUST NOT import provider adapters, must never switch on
provider names, and never interprets vendor-specific payloads. The only
thing it knows about a "provider" is the normalized ``provider`` identifier
string used for deduplication and evidence attribution.

Confidence aggregation model (documented, deterministic):

    malicious_confidence =
        base = max(confidence over available malicious signals)   # 0 when none
        + AGREEMENT_BONUS * (malicious_count - 1)                 # +10 per extra
        * CONFLICT_MULTIPLIER                       if conflict    # default 0.85
        clamped to [0, 100]

- The base is the strongest provider signal; an agreeing majority raises
  confidence by a bounded bonus per extra agreeing provider.
- An explicit conflict (malicious vs clean) damps the result BEFORE the
  clamp so an agreeing majority can never out-shout a dissenter at the
  upper boundary.
- A verdict signal that carries no confidence (0) stays 0 -- we never
  invent a certainty the provider did not supply.
- Agreement/conflict only ever shape *confidence*; they never create or
  remove a malicious classification on their own.
- ``agreement`` never counts unavailable providers: absence is not a
  dissenting vote.

Confidence sources across providers (opaque to this engine): Google Safe
Browsing ships an implied default (90/10, see its adapter); VirusTotal ships
no confidence at all, so its adapter derives one from engine counts
(evidence-derived). Both arrive as the normalized ``confidence`` field, and
this engine deliberately does not care where the number came from --
provider confidence and evidence confidence coexist at the signal layer. A
future refactor wanting to tag the *origin* of a confidence value (declared
vs derived) can extend ``ThreatIntelSignals`` without changing this file.

``DEFAULT_AGREEMENT_BONUS`` / ``DEFAULT_CONFLICT_MULTIPLIER`` are initial
tuning values, not scientifically validated constants. The service layer
passes the environment-configurable values in; both are clamped here so a
misconfigured value can never push confidence outside 0-100.
"""

from app.schemas.threat_correlation import CorrelationResult
from app.schemas.threat_intel import ThreatIntelSignals

#: Default tuning values (mirrored by config.py / .env.example).
DEFAULT_AGREEMENT_BONUS = 10
DEFAULT_CONFLICT_MULTIPLIER = 0.85

#: Hard bounds applied to any supplied tuning value.
_BONUS_BOUNDS = (0.0, 100.0)
_MULTIPLIER_BOUNDS = (0.0, 1.0)


def _clamp(value: float, low: float, high: float) -> float:
    """Bound an arbitrary number into [low, high] (NaN-safe via max/min)."""
    if value is None:
        return low
    return max(min(value, high), low)


def _round_half_up(value: float) -> int:
    """Deterministic rounding used across the threat-intel stack."""
    int_part, frac = divmod(value, 1)
    return int(int_part) + (1 if frac >= 0.5 else 0)


def correlate_threat_signals(
    signals: list[ThreatIntelSignals],
    agreement_bonus: float | None = None,
    conflict_multiplier: float | None = None,
) -> CorrelationResult:
    """Reconcile provider signals into one provider-independent result.

    ``agreement_bonus`` (0-100) and ``conflict_multiplier`` (0-1) default
    to the tuning constants and are clamped defensively regardless of what
    the caller passes.
    """
    bonus = _clamp(
        DEFAULT_AGREEMENT_BONUS if agreement_bonus is None else agreement_bonus,
        *_BONUS_BOUNDS,
    )
    multiplier = _clamp(
        DEFAULT_CONFLICT_MULTIPLIER if conflict_multiplier is None else conflict_multiplier,
        *_MULTIPLIER_BOUNDS,
    )

    # Duplicate provider results collapse into the first occurrence: one
    # provider is one independent verdict, never two.
    by_provider: dict[str, ThreatIntelSignals] = {}
    for signal in signals:
        by_provider.setdefault(signal.provider, signal)
    unique = list(by_provider.values())

    available = [s for s in unique if s.status == "available"]
    unavailable = [s for s in unique if s.status != "available"]
    malicious = [s for s in available if s.malicious]
    suspicious = [s for s in available if (not s.malicious) and s.suspicious]
    clean = [s for s in available if (not s.malicious) and (not s.suspicious)]

    has_conflict = bool(malicious) and bool(clean)

    # ------------------------------------------------------------------
    # Agreement classification (available providers only).
    # ------------------------------------------------------------------
    verdict_kinds = sum(bool(group) for group in (malicious, suspicious, clean))
    if has_conflict:
        agreement = "conflict"
    elif not available:
        agreement = "none"
    elif verdict_kinds == 1:
        agreement = "consistent"
    else:
        agreement = "partial"

    # ------------------------------------------------------------------
    # Consensus: conflicting verdicts surface as their own outcome.
    # ------------------------------------------------------------------
    if not available:
        consensus = "unavailable"
    elif has_conflict:
        consensus = "conflict"
    elif malicious:
        consensus = "malicious"
    elif suspicious:
        consensus = "suspicious"
    else:
        consensus = "clean"

    # ------------------------------------------------------------------
    # Confidence (strictly evidence-driven, bounded and deterministic).
    # ------------------------------------------------------------------
    conflict_discount = multiplier if has_conflict else 1.0
    malicious_confidence = _aggregate_confidence(malicious, bonus, conflict_discount)
    suspicious_confidence = _aggregate_confidence(suspicious, bonus, 1.0)

    categories: list[str] = []
    for source in available:
        for category in source.categories:
            if category not in categories:
                categories.append(category)

    evidence: list[str] = []
    for source in available:
        for item in source.evidence:
            if item not in evidence:
                evidence.append(item)

    # Deterministic order (alphabetical) so the result never depends on
    # the order providers ran in.
    categories = sorted(categories)
    evidence = sorted(evidence)

    return CorrelationResult(
        provider_count=len(unique),
        available_count=len(available),
        unavailable_count=len(unavailable),
        malicious_count=len(malicious),
        suspicious_count=len(suspicious),
        clean_count=len(clean),
        agreement=agreement,
        consensus=consensus,
        conflict=has_conflict,
        malicious_confidence=malicious_confidence,
        suspicious_confidence=suspicious_confidence,
        categories=categories,
        evidence=evidence,
        signals=unique,
    )


def _aggregate_confidence(
    verdict_signals: list[ThreatIntelSignals],
    bonus: float,
    multiplier: float,
) -> int:
    """Confidence attributed to one flagged direction.

    Returns 0 when no signal flags the direction, or when the flagging
    signals carry no confidence at all (we never guess). Otherwise
    ``max + bonus*(n-1)`` scaled by ``multiplier`` (1.0 when no conflict),
    rounded half-up and clamped to 0-100.
    """
    if not verdict_signals:
        return 0
    base = max((s.confidence for s in verdict_signals), default=0)
    if base <= 0:
        return 0
    raw = (base + bonus * (len(verdict_signals) - 1)) * multiplier
    return max(0, min(100, _round_half_up(raw)))