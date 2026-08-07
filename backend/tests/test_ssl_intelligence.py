"""Tests for the SSL/TLS Intelligence Engine.

Certificates are generated on the fly with :mod:`cryptography` so the
parser/intelligence layers are exercised against real X.509 objects without
any network access. Service-level tests inject a fetcher stub.
"""

import datetime

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from app.modules.ssl.intelligence import evaluate_profile
from app.modules.ssl.models import SslProfile, TlsHandshake
from app.modules.ssl.scanner import TlsUnavailableError
from app.modules.ssl.service import scan_ssl_module

UTC = datetime.timezone.utc
NOW = datetime.datetime.now(UTC)


def _sign_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _make_issuer_ca(name="CyberShield Test CA"):
    key = _sign_key()
    name_obj = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name_obj)
        .issuer_name(name_obj)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(NOW - datetime.timedelta(days=3650))
        .not_valid_after(NOW + datetime.timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    return cert


def _make_leaf_cert(
    *,
    hostname="example.com",
    days_valid=365,
    expired=False,
    key_size=2048,
    hash_alg=hashes.SHA256(),
    issuer_cert=None,
    san_hosts=None,
):
    key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, hostname)])
    issuer = issuer_cert.subject if issuer_cert is not None else subject
    not_before = NOW - datetime.timedelta(days=30)
    not_after = NOW - datetime.timedelta(days=10) if expired else NOW + datetime.timedelta(days=days_valid)
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
    )
    if san_hosts is not None:
        builder = builder.add_extension(
            x509.SubjectAlternativeName([x509.DNSName(name) for name in san_hosts]),
            critical=False,
        )
    return builder.sign(key, hash_alg)


def _handshake(hostname, cert_der, *, tls_version="TLSv1.3", cipher="TLS_AES_256_GCM_SHA384", chain_trusted=True) -> TlsHandshake:
    return TlsHandshake(
        hostname=hostname,
        tls_version=tls_version,
        cipher_suite=cipher,
        certificate_der=cert_der,
        chain_trusted=chain_trusted,
    )


def _der(cert):
    return cert.public_bytes(serialization.Encoding.DER)


def _titles(result):
    return [f.title for f in result.findings]


# ------------------------------------------------------------ intelligence units

def test_healthy_profile_scores_100():
    profile = SslProfile(
        domain="example.com",
        https_available=True,
        tls_version="TLSv1.3",
        certificate_valid=True,
        certificate_chain_valid=True,
        hostname_matches=True,
        forward_secrecy=True,
        weak_cipher=False,
        weak_signature=False,
        weak_key=False,
    )

    result = evaluate_profile(profile)

    assert result.score == 100
    assert result.findings == []
    assert result.confidence == 95


def test_missing_https_is_critical():
    profile = SslProfile(domain="plain.example", https_available=False)

    result = evaluate_profile(profile)

    assert result.score == 0
    assert [f.title for f in result.findings] == ["Missing HTTPS"]
    assert result.findings[0].severity == "critical"


def test_tls_versions_are_classified():
    for version, expected_finding in [
        ("TLSv1.0", "Outdated TLS Version"),
        ("TLSv1.1", "Outdated TLS Version"),
        ("TLSv1.2", None),
        ("TLSv1.3", None),
    ]:
        profile = SslProfile(
            domain="example.com",
            https_available=True,
            tls_version=version,
            certificate_valid=True,
            certificate_chain_valid=True,
            hostname_matches=True,
        )
        result = evaluate_profile(profile)
        if expected_finding:
            assert expected_finding in _titles(result)
            assert result.score == 70
        else:
            assert "Outdated TLS Version" not in _titles(result)


def test_expiring_certificate_flagged_medium():
    profile = SslProfile(
        domain="example.com",
        https_available=True,
        certificate_valid=True,
        expiring=True,
        expires_in_days=20,
        certificate_chain_valid=True,
        hostname_matches=True,
    )

    result = evaluate_profile(profile)

    assert "Certificate Expiring Soon" in _titles(result)
    assert result.score == 80


def test_expired_certificate_is_critical():
    profile = SslProfile(
        domain="example.com",
        https_available=True,
        expired=True,
        expires_in_days=-10,
        certificate_chain_valid=True,
        hostname_matches=True,
    )

    result = evaluate_profile(profile)

    assert "Expired SSL Certificate" in _titles(result)
    assert result.score == 40


def test_self_signed_reduces_confidence():
    profile = SslProfile(
        domain="example.com",
        https_available=True,
        self_signed=True,
        certificate_chain_valid=False,
        certificate_valid=True,
        hostname_matches=True,
    )

    result = evaluate_profile(profile)

    assert "Self-Signed Certificate" in _titles(result)
    assert result.confidence == 75
    assert "Untrusted Certificate Chain" not in _titles(result)


def test_untrusted_chain_flagged_for_ca_signed():
    profile = SslProfile(
        domain="example.com",
        https_available=True,
        self_signed=False,
        certificate_chain_valid=False,
        certificate_valid=True,
        hostname_matches=True,
    )

    result = evaluate_profile(profile)

    assert "Untrusted Certificate Chain" in _titles(result)
    assert "Self-Signed Certificate" not in _titles(result)


# ------------------------------------------------------------ service level

def test_valid_certificate_end_to_end():
    ca = _make_issuer_ca()
    leaf = _make_leaf_cert(hostname="example.com", san_hosts=["example.com"], issuer_cert=ca)
    handshake = _handshake("example.com", _der(leaf))

    result = scan_ssl_module("example.com", fetcher=lambda _h: handshake)

    assert result.status == "ok"
    assert result.score == 100
    assert result.confidence == 95
    details = result.details
    assert details["issuer"] == "CyberShield Test CA"
    assert details["subject"] == "example.com"
    assert details["tls_version"] == "TLSv1.3"
    assert details["signature_algorithm"] == "sha256WithRSAEncryption"
    assert details["public_key_algorithm"] == "rsa"
    assert details["key_size"] == 2048
    assert details["certificate_valid"] is True
    assert 0 < details["expires_in_days"] <= 365
    assert details["san_count"] == 1
    assert details["certificate_chain_valid"] is True


def test_expired_certificate_end_to_end():
    ca = _make_issuer_ca()
    leaf = _make_leaf_cert(hostname="example.com", expired=True, issuer_cert=ca, san_hosts=["example.com"])
    result = scan_ssl_module("example.com", fetcher=lambda _h: _handshake("example.com", _der(leaf)))

    assert result.status == "critical"
    assert _titles(result) == ["Expired SSL Certificate"]
    finding = result.findings[0]
    assert finding.severity == "critical"
    assert finding.explanation
    assert finding.evidence.startswith("valid_until=")
    assert finding.recommendation
    assert result.details["expires_in_days"] < 0


def test_self_signed_end_to_end():
    ca = _make_issuer_ca()
    leaf = _make_leaf_cert(hostname="internal.service", issuer_cert=ca, san_hosts=["internal.service"])
    handshake = _handshake("internal.service", _der(leaf), chain_trusted=False)

    # self-signed: use the CA cert itself as the presented certificate
    self_signed = _der(ca)
    result = scan_ssl_module("internal.service", fetcher=lambda _h: _handshake("internal.service", self_signed, chain_trusted=False))

    assert "Self-Signed Certificate" in _titles(result)
    assert result.confidence == 75


def test_missing_https_end_to_end():
    def no_tls(_hostname):
        raise TlsUnavailableError("connection refused")

    result = scan_ssl_module("plain.example", fetcher=no_tls)

    assert result.status == "critical"
    assert result.score == 0
    assert _titles(result) == ["Missing HTTPS"]
    assert result.details["https_available"] is False


def test_tls_10_detected_end_to_end():
    ca = _make_issuer_ca()
    leaf = _make_leaf_cert(hostname="example.com", issuer_cert=ca, san_hosts=["example.com"])
    handshake = _handshake("example.com", _der(leaf), tls_version="TLSv1.0", cipher="RSA-WITH-RC4-128-SHA")

    result = scan_ssl_module("example.com", fetcher=lambda _h: handshake)

    assert "Outdated TLS Version" in _titles(result)
    assert "Weak Cipher Suite" in _titles(result)
    assert result.score == 55


def test_weak_signature_algorithm_detected():
    # cryptography forbids SIGNING with SHA-1, so exercise the rule at the
    # profile level (a DEPRECATED_BROKEN-hash signature would never be
    # produced by a modern CA anyway).
    profile = SslProfile(
        domain="example.com",
        https_available=True,
        certificate_valid=True,
        certificate_chain_valid=True,
        hostname_matches=True,
        weak_signature=True,
        signature_algorithm="sha1WithRSAEncryption",
        tls_version="TLSv1.3",
    )

    result = evaluate_profile(profile)

    assert "Weak Signature Algorithm" in _titles(result)
    assert result.score == 85
    finding = result.findings[0]
    assert finding.explanation and finding.recommendation


def test_weak_key_size_detected():
    ca = _make_issuer_ca()
    leaf = _make_leaf_cert(hostname="example.com", issuer_cert=ca, san_hosts=["example.com"], key_size=1024)

    result = scan_ssl_module("example.com", fetcher=lambda _h: _handshake("example.com", _der(leaf)))

    assert "Weak Key Size" in _titles(result)
    assert result.details["key_size"] == 1024