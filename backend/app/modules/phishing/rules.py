"""Phishing evaluation rules for the phishing module."""

MODULE_NAME = "phishing"
DEFAULT_CONFIDENCE = 80

SUSPICIOUS_KEYWORDS = frozenset(
    {
        "login", "verify", "secure", "account", "banking", "update",
        "support", "paypal", "apple", "microsoft", "google", "meta",
        "password", "credential", "auth", "signin", "wallet", "crypto",
    }
)

MAX_SUBDOMAIN_DEPTH = 2
MAX_HYPHENS = 1

SUSPICIOUS_KEYWORD_PENALTY = 25
DEEP_SUBDOMAIN_PENALTY = 20
EXCESSIVE_HYPHENS_PENALTY = 15