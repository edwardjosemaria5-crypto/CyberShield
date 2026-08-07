"""Certificate helper functions for the SSL/TLS intelligence module."""

import datetime
import ipaddress
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed25519, ed448, rsa
from cryptography.x509.oid import AuthorityInformationAccessOID, ExtensionOID, NameOID


def load_certificate(der: bytes) -> x509.Certificate:
    """Parse a DER-encoded certificate."""
    return x509.load_der_x509_certificate(der)


def issuer_name(cert: x509.Certificate) -> tuple[str | None, str | None]:
    """Return (organization, common name) of the issuing CA."""
    return _name_parts(cert.issuer)


def subject_name(cert: x509.Certificate) -> tuple[str | None, str | None]:
    """Return (organization, common name) of the certificate subject."""
    return _name_parts(cert.subject)


def _name_parts(name: x509.Name) -> tuple[str | None, str | None]:
    organization = _first_attribute(name, NameOID.ORGANIZATION_NAME)
    common_name = _first_attribute(name, NameOID.COMMON_NAME)
    return organization, common_name


def _first_attribute(name: x509.Name, oid) -> str | None:
    try:
        attribute = name.get_attributes_for_oid(oid)
    except Exception:  # noqa: BLE001 - defensive against malformed names
        return None
    return attribute[0].value if attribute else None


def extract_sans(cert: x509.Certificate) -> list[str]:
    """Return the DNS/IP SAN entries of a certificate as display strings."""
    try:
        extension = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
    except x509.ExtensionNotFound:
        return []
    sans: list[str] = []
    for name in extension.value:
        if isinstance(name, x509.DNSName):
            sans.append(f"DNS:{name.value}")
        elif isinstance(name, x509.IPAddress):
            sans.append(f"IP:{name.value}")
        elif isinstance(name, x509.UniformResourceIdentifier):
            sans.append(f"URI:{name.value}")
    return sans


def san_dns_names(cert: x509.Certificate) -> list[str]:
    """Return the raw DNS names covered by the certificate SANs."""
    try:
        extension = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
    except x509.ExtensionNotFound:
        return []
    return [name.value for name in extension.value if isinstance(name, x509.DNSName)]


def is_wildcard_cert(cert: x509.Certificate) -> bool:
    """True when any SAN or the CN contains a wildcard label."""
    dns_names = san_dns_names(cert)
    _, common_name = subject_name(cert)
    candidates = [common_name] if common_name else []
    candidates.extend(dns_names)
    return any("*." in candidate for candidate in candidates if candidate)


def hostname_matches(cert: x509.Certificate, hostname: str) -> bool:
    """Check whether the certificate covers the requested hostname."""
    dns_names = san_dns_names(cert)
    _, common_name = subject_name(cert)
    if common_name:
        dns_names.append(common_name)
    target = hostname.rstrip(".").lower()
    for name in dns_names:
        if _name_covers(name, target):
            return True
    try:
        ip = ipaddress.ip_address(target)
    except ValueError:
        ip = None
    if ip is not None:
        for entry in extract_sans(cert):
            if entry.startswith("IP:") and entry[3:].strip() == target:
                return True
    return False


def _name_covers(pattern: str, hostname: str) -> bool:
    pattern = pattern.rstrip(".").lower()
    if pattern == hostname:
        return True
    if pattern.startswith("*.") and hostname.endswith(pattern[1:]):
        return hostname.count(".") == pattern.count(".")
    return False


def is_self_signed(cert: x509.Certificate) -> bool:
    """A certificate is self-signed when issuer equals subject."""
    return cert.issuer == cert.subject


def signature_algorithm(cert: x509.Certificate) -> str:
    """Human-readable signature algorithm (e.g. sha256WithRSAEncryption)."""
    name = getattr(cert.signature_algorithm_oid, "_name", None)
    if name:
        return name
    return cert.signature_algorithm_oid.dotted_string


def public_key_info(cert: x509.Certificate) -> tuple[str, int | None]:
    """Return (algorithm name, key size) for the certificate public key."""
    public_key = cert.public_key()
    if isinstance(public_key, rsa.RSAPublicKey):
        return "rsa", public_key.key_size
    if isinstance(public_key, ec.EllipticCurvePublicKey):
        return "ec", public_key.curve.key_size
    if isinstance(public_key, ed25519.Ed25519PublicKey):
        return "ed25519", None
    if isinstance(public_key, ed448.Ed448PublicKey):
        return "ed448", None
    if isinstance(public_key, dsa.DSAPublicKey):
        return "dsa", public_key.key_size
    return "unknown", None


def signature_hash_is_weak(cert: x509.Certificate) -> bool:
    """True when the certificate is signed with MD5 or SHA-1."""
    hash_oid = cert.signature_hash_algorithm
    return isinstance(hash_oid, hashes.MD5) or isinstance(hash_oid, hashes.SHA1)


def ocsp_support(cert: x509.Certificate) -> str:
    """Detect OCSP support from the Authority Information Access extension."""
    try:
        extension = cert.extensions.get_extension_for_oid(ExtensionOID.AUTHORITY_INFORMATION_ACCESS)
    except x509.ExtensionNotFound:
        return "not_available"
    ocsp_urls = [
        description.access_location.value
        for description in extension.value
        if description.access_method == AuthorityInformationAccessOID.OCSP
    ]
    return "available" if ocsp_urls else "not_available"


def to_iso(moment: datetime.datetime | datetime.date) -> str:
    return moment.isoformat()


def der_to_pem(der: bytes) -> str:
    """Convert DER certificate bytes to a PEM string (used in evidence)."""
    cert = load_certificate(der)
    return cert.public_bytes(serialization.Encoding.PEM).decode().strip()
