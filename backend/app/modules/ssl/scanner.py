"""TLS handshake retrieval.

Responsible ONLY for fetching the raw handshake information (TLS version,
cipher suite, DER certificate, chain trust verdict). Normalization and
scoring live in the parser and intelligence layers.

A first connection uses the system-trusted root context. If the chain is
rejected (e.g. self-signed or untrusted), a second unverified connection is
made purely to inspect the certificate so the scanner can still report on it.
"""

import socket
import ssl

from app.modules.ssl.models import TlsHandshake


class TlsUnavailableError(RuntimeError):
    """Raised when no TLS service can be reached for a hostname."""


def _hostname(domain: str) -> str:
    return domain.replace("https://", "").replace("http://", "").split("/")[0].split(":")[0].strip()


def fetch_tls(domain: str, timeout: float = 10.0) -> TlsHandshake:
    """Establish a TLS connection and return the raw handshake data.

    Raises:
        TlsUnavailableError: when the hostname is unreachable, refuses TLS,
            or the handshake raises an unexpected protocol error.
    """
    hostname = _hostname(domain)

    verified = _attempt(hostname, timeout, verified=True)
    if verified is not None:
        return verified

    # Not trusted by our root store: inspect the certificate anyway.
    unverified = _attempt(hostname, timeout, verified=False)
    if unverified is not None:
        return unverified

    raise TlsUnavailableError(f"Unable to establish a TLS connection to {hostname}.")


def _attempt(hostname: str, timeout: float, verified: bool) -> TlsHandshake | None:
    context = ssl.create_default_context() if verified else ssl._create_unverified_context()
    if not verified:
        context.check_hostname = False
    try:
        with socket.create_connection((hostname, 443), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cipher = ssock.cipher()
                return TlsHandshake(
                    hostname=hostname,
                    tls_version=ssock.version(),
                    cipher_suite=cipher[0] if cipher else None,
                    certificate_der=ssock.getpeercert(binary_form=True),
                    chain_trusted=verified,
                )
    except ssl.SSLCertVerificationError:
        # Trusted attempt failed verification: allow the unverified attempt.
        return None
    except (ssl.SSLError, socket.gaierror, socket.timeout, ConnectionError, OSError):
        return None
    except Exception:  # noqa: BLE001 - any handshake failure means no TLS
        return None