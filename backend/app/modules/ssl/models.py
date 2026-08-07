"""Models for the SSL/TLS intelligence module.

:class:`TlsHandshake` is the raw, provider-shaped output of the network
scanner. :class:`SslProfile` is the normalized representation consumed by
the intelligence layer; every date is ISO-8601 and every derived metric
(``expires_in_days``, ``expired``, ``expiring``) is precomputed so rule
evaluation never parses raw data.
"""

from dataclasses import dataclass, field

from pydantic import BaseModel, Field


@dataclass
class TlsHandshake:
    """Raw results of a TLS handshake, before any normalization.

    ``chain_trusted`` is True when the handshake succeeded against a default
    (trusted-root) context and False when the certificate was inspected in
    an unverified follow-up connection.
    """

    hostname: str
    tls_version: str | None = None
    cipher_suite: str | None = None
    certificate_der: bytes | None = None
    chain_trusted: bool | None = None


class SslProfile(BaseModel):
    """Normalized transport-security profile for a hostname."""

    domain: str
    https_available: bool = False

    # TLS negotiation
    tls_version: str | None = None
    cipher_suite: str | None = None
    forward_secrecy: bool | None = None
    weak_cipher: bool | None = None

    # Identity
    issuer: str = ""
    subject: str = ""
    issuer_organization: str | None = None
    issuer_common_name: str | None = None
    subject_common_name: str | None = None
    subject_organization: str | None = None
    san_entries: list[str] = Field(default_factory=list)
    san_count: int = 0
    is_wildcard: bool = False
    hostname_matches: bool | None = None

    # Cryptography
    signature_algorithm: str | None = None
    public_key_algorithm: str | None = None
    key_size: int | None = None
    weak_key: bool = False
    weak_signature: bool = False

    # Validity
    certificate_valid: bool = False
    expired: bool = False
    expiring: bool = False
    expires_in_days: int | None = None
    valid_from: str | None = None
    valid_until: str | None = None

    # Trust & ecosystem
    self_signed: bool = False
    certificate_chain_valid: bool | None = None
    ocsp_support: str = "not_available"
