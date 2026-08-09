"""WHOIS-specific scoring and detection rules.

Centralized so the intelligence layer stays declarative and operators can
tune thresholds and penalties without touching detection logic. Penalties
are deducted from a base module score of 100; the risk engine owns the
overall trust score and verdict.
"""

from dataclasses import dataclass
from typing import Final

from app.schemas.finding import Severity

MODULE_NAME: Final = "whois"

# Confidence levels: high when a real record was parsed, low when the
# lookup itself was unavailable.
DEFAULT_CONFIDENCE: Final = 80
LOW_CONFIDENCE: Final = 50

# ----------------------------------------------------------------------
# Thresholds (days)
# ----------------------------------------------------------------------
#: Domains younger than this are treated as recently registered.
RECENT_REGISTRATION_DAYS: Final = 30
#: Domains expiring within this many days are considered at risk.
EXPIRY_RISK_DAYS: Final = 30

# ----------------------------------------------------------------------
# Penalties (deducted from a base score of 100)
# ----------------------------------------------------------------------
PENALTY_RECENT_REGISTRATION: Final = 30
PENALTY_EXPIRED: Final = 40
PENALTY_EXPIRING: Final = 20
PENALTY_MISSING_REGISTRAR: Final = 15
PENALTY_MISSING_NAMESERVERS: Final = 20
PENALTY_DNSSEC_DISABLED: Final = 5
#: Failure to obtain evidence is NOT evidence of maliciousness: an
#: unavailable lookup carries no penalty and only an informational finding.
PENALTY_LOOKUP_UNAVAILABLE: Final = 0


@dataclass(frozen=True)
class Rule:
    """A single WHOIS intelligence rule."""

    title: str
    severity: Severity
    recommendation: str
    penalty: int


RECENT_REGISTRATION_RULE = Rule(
    title="Recently Registered Domain",
    severity="high",
    recommendation="Exercise caution when interacting with newly registered domains.",
    penalty=PENALTY_RECENT_REGISTRATION,
)

DOMAIN_EXPIRED_RULE = Rule(
    title="Domain Expired",
    severity="high",
    recommendation="Verify domain ownership before relying on services hosted on it.",
    penalty=PENALTY_EXPIRED,
)

DOMAIN_EXPIRING_RULE = Rule(
    title="Domain Expiring Soon",
    severity="medium",
    recommendation="Renew the domain before expiration to avoid service disruption.",
    penalty=PENALTY_EXPIRING,
)

MISSING_REGISTRAR_RULE = Rule(
    title="Missing Registrar",
    severity="medium",
    recommendation="Registry data is incomplete; cross-check the domain on a WHOIS service directly.",
    penalty=PENALTY_MISSING_REGISTRAR,
)

MISSING_NAMESERVERS_RULE = Rule(
    title="No Name Servers Detected",
    severity="high",
    recommendation="Verify DNS configuration; the domain may be unresolvable.",
    penalty=PENALTY_MISSING_NAMESERVERS,
)

DNSSEC_DISABLED_RULE = Rule(
    title="DNSSEC Disabled",
    severity="low",
    recommendation="Enable DNSSEC to protect DNS responses from tampering.",
    penalty=PENALTY_DNSSEC_DISABLED,
)

LOOKUP_UNAVAILABLE_RULE = Rule(
    title="WHOIS Lookup Unavailable",
    severity="info",
    recommendation="Retry the lookup or check registry availability.",
    penalty=PENALTY_LOOKUP_UNAVAILABLE,
)

#: Values indicating DNSSEC is explicitly turned off when a registrar
#: reports the field.
DNSSEC_DISABLED_MARKERS: Final = frozenset({"unsigned", "disabled", "false", "off", "no"})
