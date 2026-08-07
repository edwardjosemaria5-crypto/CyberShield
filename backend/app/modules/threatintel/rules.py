"""Threat intelligence evaluation rules for the threatintel module."""

MODULE_NAME = "threatintel"
DEFAULT_CONFIDENCE = 80

PHISHING_PENALTY = 30
MALWARE_PENALTY = 40
FEED_FLAGGED_PENALTY = 50

# Known test malicious domains for the local feed stub.
KNOWN_MALICIOUS_DOMAINS = frozenset(
    {"badssl.com", "phishing-example.com", "malware-test.org"}
)