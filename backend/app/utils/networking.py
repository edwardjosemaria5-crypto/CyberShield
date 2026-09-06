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

DNS rebinding / TOCTOU mitigation
---------------------------------

``validate_public_host`` only reports whether a host may be contacted; it
does not hand back the validated addresses. Modules that then connect by
hostname would re-resolve DNS at connect time, reopening a window where a
rebinding name answers public during validation but private at connect.

The single-source resolution entry point is ``resolve_public_host``: it
resolves the host once, refuses it if ANY answer is non-public (preserving
the all-or-nothing policy of ``validate_public_host``), and returns the
validated public IP literals. Callers connect to those literal IPs (never
re-resolving the hostname), while keeping the original hostname for TLS SNI
and certificate verification.
"""

import ipaddress
import re
import socket
from typing import NamedTuple

from ipaddress import _BaseAddress

#: Carrier-grade NAT block (RFC 6598) is reported as public by ``ipaddress``
#: on some Python versions; block it explicitly.
_CGNAT_NETWORK = ipaddress.ip_network("100.64.0.0/10")

#: Hostnames that must never be contacted even if they happen to resolve
#: through a public DNS record.
_RESERVED_HOSTNAMES = {"localhost", "localhost.localdomain", "local"}

#: Matches identifiers that look numeric / IP-ish but are NOT a canonical
#: ``ipaddress`` literal (e.g. ``2130706433``, ``0x7f000001``, ``0177.0.0.1``,
#: ``127.1``). These are ambiguous host forms whose resolution is OS-dependent
#: and can silently collapse to a private address, so they are refused.
_NUMERIC_HOST_RE = re.compile(r"^[0-9a-fA-FxX:.]+$")


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


class ResolvedTarget(NamedTuple):
    """Validated, pinned destination resolved ONCE by ``resolve_public_host``.

    ``host`` carries the cleaned destination host (for TLS SNI and HTTP
    ``Host``/certificate verification), while ``addresses`` holds the
    validated public IP literals (IPv4 first, then IPv6) that a caller must
    actually connect to — never re-resolving the hostname.
    """

    host: str
    addresses: tuple[str, ...]

    @property
    def ipv4(self) -> tuple[str, ...]:
        return tuple(a for a in self.addresses if ":" not in a)

    @property
    def ipv6(self) -> tuple[str, ...]:
        return tuple(a for a in self.addresses if ":" in a)


def resolve_public_host(host: str) -> tuple[ResolvedTarget | None, str | None]:
    """Resolve a destination host ONCE and pin the validated public IPs.

    This is the single authoritative resolution for outbound connections.
    Unlike ``validate_public_host`` (which only returns a verdict), it hands
    back the actual literal addresses a caller must connect to, so a hostname
    is never re-resolved at connect time (closing the DNS-rebinding/TOCTOU
    window). Behaviors are preserved from ``validate_public_host``:

    - A host is refused if ANY resolved answer is non-public.
    - Ambiguous non-canonical numeric identifiers are refused.
    - An empty or unresolvable host returns ``(None, None)``; the caller
      treats that as its own module error path (no connection is made).

    Returns:
        ``(target, None)`` on success, ``(None, reason)`` when refused, or
        ``(None, None)`` when the host is empty or does not resolve.
    """
    target_host = parse_host(host)
    if not target_host:
        return None, "Target has no host."

    if target_host in _RESERVED_HOSTNAMES or ".localhost" in target_host or ".local" in target_host:
        return None, f"Target '{target_host}' is a private hostname; refusing."

    try:
        parsed_ip = ipaddress.ip_address(target_host)
    except ValueError:
        parsed_ip = None

    if parsed_ip is not None:
        if _is_private_address(parsed_ip):
            return None, f"Target IP {target_host} is private/reserved; refusing."
        return ResolvedTarget(target_host, (target_host,)), None

    if _NUMERIC_HOST_RE.match(target_host):
        return None, f"Target '{target_host}' is a non-canonical numeric host; refusing."

    try:
        infos = socket.getaddrinfo(target_host, None, proto=socket.IPPROTO_TCP)
    except socket.gaierror:
        return None, None
    except OSError:
        return None, None

    addresses: list[str] = []
    seen: set[str] = set()
    for info in infos:
        value = info[4][0]
        try:
            address = ipaddress.ip_address(value)
        except ValueError:
            continue
        if _is_private_address(address):
            return None, f"Target '{target_host}' resolves to a private/reserved address; refusing."
        key = address.compressed
        if key in seen:
            continue
        seen.add(key)
        addresses.append(key)

    if not addresses:
        return None, None

    addresses.sort(key=lambda item: (ipaddress.ip_address(item).version, item))
    return ResolvedTarget(target_host, tuple(addresses)), None
