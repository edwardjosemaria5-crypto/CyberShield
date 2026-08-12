"""Outbound-network safety helpers for modules that contact scan targets.

Purpose: modules that fetch a user-supplied host (HTTP header retrieval,
TCP port checks) must never be steered at the operator's internal network.
``validate_public_host`` rejects hostnames whose DNS resolution reaches a
private, loopback, link-local, reserved, multicast or carrier-grade-NAT
(100.64.0.0/10) address, and rejects well-known private hostname aliases
(e.g. ``localhost``) without even resolving.

Design notes:

- Blocking is decided on ALL resolved addresses: if any record is
  non-public, the host is refused (defense in depth).
- A host that fails to resolve is NOT blocked here — callers already treat
  resolution failure as a module error, and no connection is made without
  resolving.
- The helper is pure Python (``socket``/``ipaddress``); no new dependency.
"""

import ipaddress
import socket

from ipaddress import _BaseAddress

#: Carrier-grade NAT block (RFC 6598) is reported as public by ``ipaddress``
#: on some Python versions; block it explicitly.
_CGNAT_NETWORK = ipaddress.ip_network("100.64.0.0/10")

#: Hostnames that must never be contacted even if they happen to resolve
#: through a public DNS record.
_RESERVED_HOSTNAMES = {"localhost", "localhost.localdomain", "local"}


def _is_private_address(address: _BaseAddress) -> bool:
    """True when an IP is never a legitimate remote scan target."""
    if address in _CGNAT_NETWORK:
        return True
    return (
        address.is_private
        or address.is_loopback
        or address.is_link_local
        or address.is_reserved
        or address.is_multicast
        or address.is_unspecified
    )


def parse_host(host: str) -> str:
    """Extract the destination hostname from a raw host string.

    Strips scheme, path, URL userinfo (``user:pass@``), port and IPv6
    brackets. Userinfo is discarded so it can never be mistaken for the
    destination host: ``http://user@127.0.0.1/`` yields ``127.0.0.1``.
    """
    raw = host or ""
    if raw.startswith(("https://", "http://")):
        raw = raw.split("://", 1)[1]
    raw = raw.split("/", 1)[0].strip().lower()
    if "@" in raw:
        raw = raw.rsplit("@", 1)[1]
    if raw.startswith("["):
        raw = raw.split("]", 1)[0].lstrip("[")
    else:
        try:
            ipaddress.ip_address(raw)  # IPv6 literal (no brackets) — keep as-is
        except ValueError:
            raw = raw.split(":", 1)[0]
    return raw


def validate_public_host(host: str) -> str | None:
    """Validate that a target host may be contacted remotely.

    Returns ``None`` when the host is public and reachable, or a
    human-readable reason string when it must be refused. Never raises.
    """
    host = parse_host(host)
    if not host:
        return "Target has no host."
    if host in _RESERVED_HOSTNAMES or host.endswith(".localhost") or host.endswith(".local"):
        return f"Target '{host}' is a private hostname; refusing."
    try:
        parsed_ip = ipaddress.ip_address(host)  # literal: no DNS needed
    except ValueError:
        parsed_ip = None
    if parsed_ip is not None:
        if _is_private_address(parsed_ip):
            return f"Target IP {host} is private/reserved; refusing."
        return None

    try:
        infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    except socket.gaierror:
        return None  # unresolved hosts are handled by the module's own error path

    for info in infos:
        address = info[4][0]
        try:
            if _is_private_address(ipaddress.ip_address(address)):
                return f"Target '{host}' resolves to a private/reserved address; refusing."
        except ValueError:
            continue
    return None