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
from app.utils.networking import resolve_public_host


class TlsUnavailableError(RuntimeError):
    """Raised when no TLS service can be reached for a hostname."""


class BlockedTargetError(RuntimeError):
    """Raised when the target host is refused by the outbound safety guard."""


def _hostname(domain: str) -> str:
    return domain.replace("https://", "").replace("http://", "").split("/")[0].split(":")[0].strip()


def fetch_tls(domain: str, timeout: float = 10.0) -> TlsHandshake:
    """Establish a TLS connection and return the raw handshake data.

    The target is resolved ONCE by the outbound safety guard, which returns
    the validated public IP literals to connect to. Connecting to a literal IP
    (never re-resolving the hostname at connect time) closes the DNS-rebinding
    /TOCTOU window while the hostname is preserved for TLS SNI and certificate
    verification.

    Raises:
        TlsUnavailableError: when the hostname is unresolved or unreachable,
            refuses TLS, or the handshake raises an unexpected protocol error.
        BlockedTargetError: when the target host is refused by the outbound
            safety guard (private, loopback, link-local, reserved, CGNAT,
            multicast, non-canonical numeric, or well-known private hostname).
    """
    hostname = _hostname(domain)

    target, reason = resolve_public_host(domain)
    if reason:
        raise BlockedTargetError(reason)
    if target is None:
        raise TlsUnavailableError(f"Unable to resolve {hostname}; no TLS connection made.")

    verified = _attempt(hostname, target.addresses, timeout, verified=True)
    if verified is not None:
        return verified

    # Not trusted by our root store: inspect the certificate anyway.
    unverified = _attempt(hostname, target.addresses, timeout, verified=False)
    if unverified is not None:
        return unverified

    raise TlsUnavailableError(f"Unable to establish a TLS connection to {hostname}.")


def _attempt(hostname: str, addresses: tuple[str, ...], timeout: float, verified: bool) -> TlsHandshake | None:
    """Try a TLS handshake against each pinned literal IP.

    ``addresses`` are validated public IP literals so no DNS re-resolution
    happens at connect time; ``hostname`` is only ever used as the SNI /
    certificate-verification identity, never as a connect address.
    """
    if not addresses:
        return None
    context = ssl.create_default_context() if verified else ssl._create_unverified_context()
    if not verified:
        context.check_hostname = False
    for address in addresses:
        try:
            with socket.create_connection((address, 443), timeout=timeout) as sock:
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
            continue
        except Exception:  # noqa: BLE001 - any handshake failure means no TLS
            continue
    return None