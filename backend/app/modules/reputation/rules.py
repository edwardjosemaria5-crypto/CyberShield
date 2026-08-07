"""Reputation evaluation rules for the reputation module."""

MODULE_NAME = "reputation"
DEFAULT_CONFIDENCE = 85

BLACKLISTED_PENALTY = 40
NEWLY_REGISTERED_PENALTY = 25
HIGH_RISK_TLD_PENALTY = 15

# TLD tiers used by the popularity analyzer.
HIGH_TRUST_TLDS = frozenset({"gov", "edu", "mil"})
STANDARD_TLDS = frozenset({"com", "org", "net", "io", "co", "uk", "ca", "de", "fr"})
SUSPICIOUS_TLDS = frozenset({"zip", "mov", "top", "xyz", "click", "download", "racing", "work"})