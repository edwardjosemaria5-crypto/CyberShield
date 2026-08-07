"""Structural URL analysis rules.

These rules are purely structural: they describe suspicious URL *shapes*
(IP hosts, missing HTTPS, punycode, unusual lengths) rather than external
reputation signals. The final trust score is owned by the risk engine.
"""

SUSPICIOUS_KEYWORDS = frozenset(
    {
        "login",
        "secure",
        "account",
        "verify",
        "update",
        "bank",
        "paypal",
        "confirm",
        "signin",
    }
)

# Risk deductions applied per structural indicator. These are module-local
# weights and must not be confused with the risk-engine module weights.
IP_ADDRESS_PENALTY = 25
NO_HTTPS_PENALTY = 20
URL_LENGTH_PENALTY = 10
PUNYCODE_PENALTY = 10
NON_STANDARD_CHARS_PENALTY = 5
SUSPICIOUS_KEYWORD_PENALTY = 10
MANY_SUBDOMAINS_PENALTY = 10

MAX_URL_LENGTH = 100
MAX_SUBDOMAINS = 3