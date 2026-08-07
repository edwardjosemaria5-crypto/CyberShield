"""SSL/TLS scoring and detection rules.

Centralized so the intelligence layer stays declarative and operators can
tune thresholds and penalties without touching detection logic. Penalties
are deducted from a base module score of 100; the risk engine owns the
overall trust score and verdict.
"""

from dataclasses import dataclass
from typing import Final

from app.schemas.finding import Severity

MODULE_NAME: Final = "ssl"

# Confidence levels: high when the handshake was verified against trusted
# roots, reduced when the certificate could only be inspected unverified.
DEFAULT_CONFIDENCE: Final = 95
REDUCED_CONFIDENCE: Final = 75

# ----------------------------------------------------------------------
# Thresholds
# ----------------------------------------------------------------------
#: Certificates with fewer remaining days than this are "expiring soon".
EXPIRING_SOON_DAYS: Final = 30
#: RSA keys below this size are considered weak.
MIN_RSA_KEY_SIZE: Final = 2048
#: Elliptic-curve keys below this size are considered weak.
MIN_EC_KEY_SIZE: Final = 256

# ----------------------------------------------------------------------
# Penalties (deducted from a base score of 100)
# ----------------------------------------------------------------------
PENALTY_MISSING_HTTPS: Final = 100
PENALTY_EXPIRED: Final = 60
PENALTY_EXPIRING: Final = 20
PENALTY_SELF_SIGNED: Final = 40
PENALTY_UNTRUSTED_CHAIN: Final = 30
PENALTY_OLD_TLS: Final = 30
PENALTY_WEAK_SIGNATURE: Final = 15
PENALTY_WEAK_KEY: Final = 15
PENALTY_HOSTNAME_MISMATCH: Final = 50
PENALTY_WEAK_CIPHER: Final = 15
PENALTY_NO_FORWARD_SECRECY: Final = 10

# ----------------------------------------------------------------------
# Cipher / TLS classification
# ----------------------------------------------------------------------
#: TLS versions that are cryptographically obsolete.
WEAK_TLS_VERSIONS: Final = frozenset({"TLSv1.0", "TLSv1.1", "TLSv1"})
#: Cipher-suite markers that indicate forward secrecy is in use.
FORWARD_SECRECY_MARKERS: Final = ("ECDHE", "DHE-", "TLS_AES", "TLS_CHACHA")
#: Cipher-suite markers that indicate a cryptographically weak primitive.
WEAK_CIPHER_MARKERS: Final = ("RC4", "3DES", "DES-", "CBC")


@dataclass(frozen=True)
class SslRule:
    """A single SSL/TLS intelligence rule."""

    title: str
    severity: Severity
    explanation: str
    recommendation: str
    penalty: int


MISSING_HTTPS_RULE = SslRule(
    title="Missing HTTPS",
    severity="critical",
    explanation=(
        "The site does not serve traffic over TLS. All data exchanged with it, "
        "including credentials, cookies, and personal information, travels in "
        "plaintext and can be read or modified by anyone on the network path."
    ),
    recommendation="Enable HTTPS by installing a certificate from a trusted Certificate Authority.",
    penalty=PENALTY_MISSING_HTTPS,
)

EXPIRED_CERT_RULE = SslRule(
    title="Expired SSL Certificate",
    severity="critical",
    explanation=(
        "The certificate is past its validity end date. Browsers will show "
        "fatal trust warnings, and automated clients will refuse to connect, "
        "which typically signals an unmaintained service."
    ),
    recommendation="Renew the certificate immediately.",
    penalty=PENALTY_EXPIRED,
)

EXPIRING_CERT_RULE = SslRule(
    title="Certificate Expiring Soon",
    severity="medium",
    explanation=(
        "Certificates nearing expiration may lead to service disruption or "
        "user trust warnings if not renewed in time."
    ),
    recommendation="Renew the certificate before expiration.",
    penalty=PENALTY_EXPIRING,
)

SELF_SIGNED_RULE = SslRule(
    title="Self-Signed Certificate",
    severity="high",
    explanation=(
        "Self-signed certificates are not trusted by browsers and may indicate "
        "an internal or improperly configured service. They also prevent "
        "verification that the certificate actually belongs to the operator."
    ),
    recommendation="Use a certificate issued by a trusted Certificate Authority.",
    penalty=PENALTY_SELF_SIGNED,
)

UNTRUSTED_CHAIN_RULE = SslRule(
    title="Untrusted Certificate Chain",
    severity="high",
    explanation=(
        "The certificate chain does not validate against trusted root stores. "
        "This can be caused by an incomplete chain, an unknown issuer, or a "
        "revoked intermediate, and it breaks browser trust."
    ),
    recommendation="Serve the full certificate chain and use a publicly trusted CA.",
    penalty=PENALTY_UNTRUSTED_CHAIN,
)

OLD_TLS_RULE = SslRule(
    title="Outdated TLS Version",
    severity="high",
    explanation=(
        "Older TLS versions contain known weaknesses and are no longer "
        "recommended. TLS 1.0 and 1.1 are formally deprecated and vulnerable "
        "to downgrade and protocol-level attacks."
    ),
    recommendation="Upgrade to TLS 1.2 or TLS 1.3.",
    penalty=PENALTY_OLD_TLS,
)

WEAK_SIGNATURE_RULE = SslRule(
    title="Weak Signature Algorithm",
    severity="medium",
    explanation=(
        "MD5 and SHA-1 are cryptographically broken: collision attacks let an "
        "attacker forge certificates with the same signature, undermining the "
        "integrity guarantees the signature is supposed to provide."
    ),
    recommendation="Re-issue the certificate with SHA-256 or a stronger hash.",
    penalty=PENALTY_WEAK_SIGNATURE,
)

WEAK_KEY_RULE = SslRule(
    title="Weak Key Size",
    severity="medium",
    explanation=(
        "Keys that are too short can be factored or brute-forced with modest "
        "hardware, allowing an attacker to impersonate the service. "
        "2048-bit RSA (or 256-bit ECC) is the current minimum."
    ),
    recommendation="Re-issue the certificate with a 2048-bit RSA or 256-bit ECC key.",
    penalty=PENALTY_WEAK_KEY,
)

HOSTNAME_MISMATCH_RULE = SslRule(
    title="Certificate Hostname Mismatch",
    severity="critical",
    explanation=(
        "The certificate does not cover the visited hostname. Browsers block "
        "such connections because the certificate cannot prove ownership of "
        "the domain, enabling impersonation attacks."
    ),
    recommendation="Issue a certificate that covers the requested hostname (or its SANs).",
    penalty=PENALTY_HOSTNAME_MISMATCH,
)

WEAK_CIPHER_RULE = SslRule(
    title="Weak Cipher Suite",
    severity="medium",
    explanation=(
        "The negotiated cipher suite relies on deprecated primitives "
        "(RC4, 3DES, or CBC modes) that are vulnerable to practical attacks "
        "when combined with modern protocol features."
    ),
    recommendation="Restrict the server to AEAD cipher suites such as AES-GCM or ChaCha20.",
    penalty=PENALTY_WEAK_CIPHER,
)

NO_FORWARD_SECRECY_RULE = SslRule(
    title="No Forward Secrecy",
    severity="low",
    explanation=(
        "The negotiated key exchange does not provide forward secrecy, so a "
        "compromised server private key would allow decrypting all recorded "
        "past sessions."
    ),
    recommendation="Prefer ephemeral ECDHE/DHE key exchanges.",
    penalty=PENALTY_NO_FORWARD_SECRECY,
)
