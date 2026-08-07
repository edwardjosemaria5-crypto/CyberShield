"""DNS-specific scoring and detection rules.

Centralized so the intelligence layer stays declarative and operators can
tune thresholds and penalties without touching detection logic. Penalties
are deducted from a base module score of 100; the risk engine owns the
overall trust score and verdict.
"""

from dataclasses import dataclass
from typing import Final

from app.schemas.finding import Severity

MODULE_NAME: Final = "dns"

# Confidence levels: high for a successful resolution, low when the
# resolver itself failed.
DEFAULT_CONFIDENCE: Final = 90
LOW_CONFIDENCE: Final = 50

# ----------------------------------------------------------------------
# Thresholds
# ----------------------------------------------------------------------
#: More name servers than this is considered excessive.
MAX_NAMESERVERS: Final = 5
#: TTLs below this (seconds) suggest a rapidly changing / fast-flux zone.
LOW_TTL_THRESHOLD: Final = 60

# ----------------------------------------------------------------------
# Penalties (deducted from a base score of 100)
# ----------------------------------------------------------------------
PENALTY_DOMAIN_NOT_RESOLVING: Final = 60
PENALTY_MISSING_SPF: Final = 15
PENALTY_MISSING_DMARC: Final = 15
PENALTY_MISSING_MX: Final = 5
PENALTY_DNSSEC_DISABLED: Final = 5
PENALTY_MISSING_CAA: Final = 0
PENALTY_SUSPICIOUS_CAA: Final = 10
PENALTY_EXCESSIVE_NAMESERVERS: Final = 10
PENALTY_DUPLICATE_NAMESERVERS: Final = 10
PENALTY_SINGLE_NAMESERVER: Final = 5
PENALTY_LOW_TTL: Final = 2
PENALTY_INCONSISTENT_RESOLUTION: Final = 15
PENALTY_MISSING_DKIM: Final = 0


@dataclass(frozen=True)
class DnsRule:
    """A single DNS intelligence rule."""

    title: str
    severity: Severity
    explanation: str
    recommendation: str
    penalty: int


DOMAIN_NOT_RESOLVING_RULE = DnsRule(
    title="Domain Does Not Resolve",
    severity="high",
    explanation=(
        "The domain has no A or AAAA records, so it cannot be reached on the "
        "internet. Phishing and fraudulent campaigns frequently use "
        "throwaway domains that are abandoned after a short lifetime."
    ),
    recommendation="Verify the domain spelling; if it is your domain, restore DNS records.",
    penalty=PENALTY_DOMAIN_NOT_RESOLVING,
)

MISSING_SPF_RULE = DnsRule(
    title="SPF Record Missing",
    severity="medium",
    explanation=(
        "Without an SPF record, attackers may have an easier time spoofing "
        "emails that appear to originate from this domain, because receiving "
        "servers cannot verify which hosts are authorized to send mail."
    ),
    recommendation="Publish an SPF record (v=spf1) listing the servers authorized to send mail.",
    penalty=PENALTY_MISSING_SPF,
)

MISSING_DMARC_RULE = DnsRule(
    title="DMARC Policy Missing",
    severity="medium",
    explanation=(
        "Without a DMARC policy on _dmarc.<domain>, receiving servers do not "
        "know what to do with spoofed mail that fails SPF/DKIM checks, so "
        "impersonation attempts may still reach inboxes."
    ),
    recommendation="Publish a DMARC record (v=DMARC1; p=quarantine or reject) on _dmarc.<domain>.",
    penalty=PENALTY_MISSING_DMARC,
)

MISSING_MX_RULE = DnsRule(
    title="No MX Records",
    severity="low",
    explanation=(
        "The domain has no mail exchanger records. This is expected for "
        "domains that do not receive email, but on sites that claim to send "
        "mail it can indicate an incomplete or abandoned configuration."
    ),
    recommendation="Configure MX records if the domain is expected to receive email.",
    penalty=PENALTY_MISSING_MX,
)

DNSSEC_DISABLED_RULE = DnsRule(
    title="DNSSEC Disabled",
    severity="low",
    explanation=(
        "Without DNSSEC, DNS responses for this domain cannot be "
        "cryptographically verified, leaving resolvers vulnerable to DNS "
        "spoofing or cache poisoning attacks."
    ),
    recommendation="Enable DNSSEC signing at your registrar and publish a DNSKEY record.",
    penalty=PENALTY_DNSSEC_DISABLED,
)

MISSING_CAA_RULE = DnsRule(
    title="CAA Record Missing",
    severity="info",
    explanation=(
        "CAA records let a domain declare which Certificate Authorities are "
        "allowed to issue certificates for it. Without them, any CA may "
        "issue certificates for the domain."
    ),
    recommendation="Publish a CAA record restricting certificate issuance to your CA.",
    penalty=PENALTY_MISSING_CAA,
)

SUSPICIOUS_CAA_RULE = DnsRule(
    title="Suspicious CAA Configuration",
    severity="medium",
    explanation=(
        "CAA records exist but none authorize a specific issuer ('issue' "
        "tag), which is non-standard and may indicate misconfiguration or "
        "intentional confusion."
    ),
    recommendation="Publish explicit CAA 'issue' records for your Certificate Authority.",
    penalty=PENALTY_SUSPICIOUS_CAA,
)

EXCESSIVE_NAMESERVERS_RULE = DnsRule(
    title="Excessive Name Servers",
    severity="medium",
    explanation=(
        "An unusually large number of name servers is atypical and can "
        "indicate delegation churn, misconfiguration, or infrastructure "
        "abuse such as fast-flux hosting."
    ),
    recommendation="Consolidate delegation to a small set of well-maintained name servers.",
    penalty=PENALTY_EXCESSIVE_NAMESERVERS,
)

DUPLICATE_NAMESERVERS_RULE = DnsRule(
    title="Duplicate Name Servers",
    severity="medium",
    explanation=(
        "The same name server appears more than once in the delegation, "
        "which is redundant: it does not add resilience and points to a "
        "poorly maintained zone configuration."
    ),
    recommendation="Remove duplicate entries from the name server list.",
    penalty=PENALTY_DUPLICATE_NAMESERVERS,
)

SINGLE_NAMESERVER_RULE = DnsRule(
    title="Single Name Server",
    severity="low",
    explanation=(
        "A single name server is a single point of failure: if it goes "
        "down, the entire domain becomes unresolvable."
    ),
    recommendation="Use at least two independent name servers for redundancy.",
    penalty=PENALTY_SINGLE_NAMESERVER,
)

LOW_TTL_RULE = DnsRule(
    title="Very Low TTL Values",
    severity="info",
    explanation=(
        "Very low TTLs make DNS records change rapidly, which is common in "
        "fast-flux hosting used by malware and phishing infrastructure."
    ),
    recommendation="Raise TTLs to standard values (300s+) unless changes are frequent and intentional.",
    penalty=PENALTY_LOW_TTL,
)

INCONSISTENT_RESOLUTION_RULE = DnsRule(
    title="Inconsistent DNS Resolution",
    severity="medium",
    explanation=(
        "Different resolvers return different addresses for the domain. "
        "This 'split-horizon' behavior is a hallmark of DNS manipulation "
        "or geo-split phishing infrastructure."
    ),
    recommendation="Investigate the zone; ensure all resolvers observe the same records.",
    penalty=PENALTY_INCONSISTENT_RESOLUTION,
)

DKIM_NOT_DETECTED_RULE = DnsRule(
    title="DKIM Not Detected",
    severity="info",
    explanation=(
        "No DKIM signing selector was found. Without DKIM, receiving "
        "servers cannot verify that email headers and content were not "
        "tampered with in transit."
    ),
    recommendation="Sign outbound email with DKIM and publish the public key at <selector>._domainkey.",
    penalty=PENALTY_MISSING_DKIM,
)


