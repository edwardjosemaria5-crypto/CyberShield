"""Blacklist evaluation rules for the blacklist module."""

MODULE_NAME = "blacklist"
DEFAULT_CONFIDENCE = 85

# Public DNSBLs queried with the reversed client IP.
DNSBL_LISTS = [
    "zen.spamhaus.org",
    "bl.spamcop.net",
    "dnsbl.sorbs.net",
    "b.barracudacentral.org",
]

# Well-known malicious domains used by the static feed stub.
KNOWN_MALICIOUS_DOMAINS = frozenset(
    {"badssl.com", "phishing-example.com", "malware-test.org"}
)

BLACKLISTED_PENALTY = 45