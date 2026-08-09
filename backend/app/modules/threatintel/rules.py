"""Threat intelligence evaluation rules for the threatintel module.

Confidence model (documented, deterministic, configurable below):

  Penalty_effective = base_penalty * (signal.confidence / 100)

- The provider penalty is scaled linearly by the signal's reported
  confidence (0-100, validated by ``ThreatIntelSignals``). High-confidence
  evidence therefore has more impact than low-confidence evidence, while a
  zero-confidence verdict (provider reported a match without any confidence
  information) contributes no penalty at all — we never guess a certainty
  the provider did not supply.
- Rounding is round-half-up so scales are stable and testable.
- ``_provider_penalty`` clamps defensively: values outside 0-100 can only
  arrive through a hand-crafted object, not through the validated schema.
- Clean and unavailable providers always contribute zero penalty.
- The summed provider penalties from every adapter are capped by
  ``PROVIDER_PENALTY_CAP`` so multiple detections can never drop a domain
  below the intended floor.

Severity ladder: a verdict's severity also reflects confidence so the level
never claims more certainty than the signal carries (a low-confidence
malicious match is "high", not "critical").
"""

MODULE_NAME = "threatintel"
DEFAULT_CONFIDENCE = 80

PHISHING_PENALTY = 30
MALWARE_PENALTY = 40
FEED_FLAGGED_PENALTY = 50

# Penalties applied when an external provider reports a verdict.
# These are additive to the local heuristics penalties; an unavailable
# provider contributes nothing (absent provider is NOT a negative signal).
SAFE_BROWSING_MALICIOUS_PENALTY = 35
SAFE_BROWSING_SUSPICIOUS_PENALTY = 15

# Cap the penalty contributed by provider verdicts so a domain is never
# pushed below zero by external signals alone.
PROVIDER_PENALTY_CAP = 40

# Confidence thresholds/ a verdict must reach to count as high certainty.
# Fatigue severity mapping uses these to keep assertions honest.
CONFIDENCE_HIGH = 80
CONFIDENCE_MEDIUM = 40

# Known test malicious domains for the local feed stub.
KNOWN_MALICIOUS_DOMAINS = frozenset(
    {"badssl.com", "phishing-example.com", "malware-test.org"}
)