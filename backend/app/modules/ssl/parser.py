"""Normalize raw TLS handshake data into a :class:`SslProfile`.

Extracts identity, cryptographic, and validity details from the DER
certificate using :mod:`cryptography`. Always degrades gracefully: any
certificate that cannot be parsed produces a profile with the available
fields populated and the rest as ``None``/``False``.
"""

import datetime
import logging
from typing import Any

from app.modules.ssl import utils
from app.modules.ssl.models import SslProfile, TlsHandshake
from app.modules.ssl.rules import EXPIRING_SOON_DAYS, MIN_EC_KEY_SIZE, MIN_RSA_KEY_SIZE
from app.modules.ssl.utils import load_certificate

logger = logging.getLogger("cybershield.ssl")


def _utc_now() -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc)


def parse_handshake(handshake: TlsHandshake | None) -> SslProfile:
    """Convert raw TLS handshake data into a normalized profile.

    A ``None`` handshake (or one without certificate bytes) yields a profile
    with ``https_available`` False so the intelligence layer can report the
    Missing HTTPS finding.
    """
    domain = handshake.hostname if handshake else ""
    try:
        cert = utils.load_certificate(handshake.certificate_der) if handshake and handshake.certificate_der else None
    except Exception as exc:  # noqa: BLE001 - malformed cert must not abort the scan
        logger.warning("Unable to parse certificate for %s: %s", domain, exc)
        cert = None

    profile = SslProfile(
        domain=domain,
        https_available=handshake is not None,
        tls_version=handshake.tls_version if handshake else None,
        cipher_suite=handshake.cipher_suite if handshake else None,
        certificate_chain_valid=handshake.chain_trusted if handshake else None,
    )

    if not profile.https_available:
        return profile

    profile.forward_secrecy = _forward_secrecy(profile.tls_version, profile.cipher_suite)
    profile.weak_cipher = _weak_cipher(profile.cipher_suite)

    if cert is None:
        return profile

    issuer_org, issuer_cn = utils.issuer_name(cert)
    subject_org, subject_cn = utils.subject_name(cert)
    sig_alg = utils.signature_algorithm(cert)
    pub_alg, key_size = utils.public_key_info(cert)
    sans = utils.extract_sans(cert)

    profile.issuer = issuer_org or issuer_cn or "Unknown"
    profile.subject = subject_cn or domain
    profile.issuer_organization = issuer_org
    profile.issuer_common_name = issuer_cn
    profile.subject_common_name = subject_cn
    profile.subject_organization = subject_org
    profile.san_entries = sans
    profile.san_count = len(sans)
    profile.is_wildcard = utils.is_wildcard_cert(cert)
    profile.signature_algorithm = sig_alg
    profile.public_key_algorithm = pub_alg
    profile.key_size = key_size
    profile.weak_key = _is_weak_key(pub_alg, key_size)
    profile.weak_signature = utils.signature_hash_is_weak(cert)
    profile.self_signed = utils.is_self_signed(cert)
    profile.ocsp_support = utils.ocsp_support(cert)
    profile.hostname_matches = utils.hostname_matches(cert, domain)

    profile.valid_from = utils.to_iso(cert.not_valid_before_utc)
    profile.valid_until = utils.to_iso(cert.not_valid_after_utc)

    now = _utc_now()
    profile.expired = cert.not_valid_after_utc < now
    profile.expiring = (
        not profile.expired and (cert.not_valid_after_utc - now).days <= EXPIRING_SOON_DAYS
    )
    profile.expires_in_days = (cert.not_valid_after_utc - now).days
    profile.certificate_valid = (
        cert.not_valid_before_utc <= now <= cert.not_valid_after_utc
    )

    return profile


def _is_weak_key(public_key_algorithm: str | None, key_size: int | None) -> bool:
    if key_size is None:
        return False
    if public_key_algorithm == "rsa":
        return key_size < MIN_RSA_KEY_SIZE
    if public_key_algorithm == "ec":
        return key_size < MIN_EC_KEY_SIZE
    return False


def _forward_secrecy(tls_version: str | None, cipher_suite: str | None) -> bool | None:
    """True when the negotiated suite provides forward secrecy."""
    if not cipher_suite:
        return None
    suite = cipher_suite.upper()
    if "TLS_AES" in suite or "TLS_CHACHA" in suite:
        return True  # TLS 1.3 suites are always ephemeral
    return "ECDHE" in suite or suite.startswith("DHE-")


def _weak_cipher(cipher_suite: str | None) -> bool | None:
    """True when the negotiated suite relies on deprecated primitives."""
    if not cipher_suite:
        return None
    suite = cipher_suite.upper()
    if "TLS_AES" in suite or "TLS_CHACHA" in suite:
        return False  # TLS 1.3 AEAD suites are not weak
    return any(marker in suite for marker in ("RC4", "3DES", "DES-", "CBC"))


def parse_certificate(cert_der: bytes) -> dict[str, Any]:
    """Standalone normalization of a DER certificate (helper for tests)."""
    cert = utils.load_certificate(cert_der)
    pub_alg, key_size = utils.public_key_info(cert)
    return {
        "issuer_organization": utils.issuer_name(cert)[0],
        "issuer_common_name": utils.issuer_name(cert)[1],
        "subject_common_name": utils.subject_name(cert)[1],
        "san_entries": utils.extract_sans(cert),
        "is_wildcard": utils.is_wildcard_cert(cert),
        "signature_algorithm": utils.signature_algorithm(cert),
        "public_key_algorithm": pub_alg,
        "key_size": key_size,
        "self_signed": utils.is_self_signed(cert),
        "ocsp_support": utils.ocsp_support(cert),
        "signature_is_weak": utils.signature_hash_is_weak(cert),
    }