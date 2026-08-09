"""Tests for the outbound-network safety guard (D1 hardening).

The guard prevents scan modules from contacting private/reserved networks,
both for IP literals and for hostnames whose DNS resolves to such addresses.
"""

import socket

from app.modules.headers.scanner import scan_headers_module
from app.modules.ports.scanner import scan_ports_module
from app.utils.networking import validate_public_host

_PRIVATE_IP_LITERALS = [
    "10.0.0.1",
    "127.0.0.1",
    "169.254.169.254",
    "172.16.0.1",
    "192.168.1.1",
    "100.64.0.1",
    "0.0.0.0",
    "::1",
    "fe80::1",
    "fc00::1",
]

_PUBLIC_IP_LITERALS = ["8.8.8.8", "1.1.1.1", "93.184.216.34", "2606:4700:4700::1111"]


def test_private_ip_literals_are_refused():
    for ip in _PRIVATE_IP_LITERALS:
        reason = validate_public_host(ip)
        assert reason is not None, f"expected {ip} to be refused"
        assert "private" in reason or "reserved" in reason


def test_public_ip_literals_are_allowed():
    for ip in _PUBLIC_IP_LITERALS:
        assert validate_public_host(ip) is None, f"expected {ip} to be allowed"


def test_private_hostnames_are_refused_without_resolution():
    for name in ("localhost", "localhost.localdomain", "local", "db.localhost"):
        assert validate_public_host(name) is not None


def test_hostname_resolving_to_private_ip_is_refused(monkeypatch):
    def fake_getaddrinfo(host, *_args, **_kwargs):
        return [(socket.AF_INET, socket.SOCK_STREAM, 0, "", ("10.1.2.3", 0))]

    monkeypatch.setattr("app.utils.networking.socket.getaddrinfo", fake_getaddrinfo)
    assert "private" in validate_public_host("internal.example.internal")


def test_hostname_resolving_to_public_ip_is_allowed(monkeypatch):
    def fake_getaddrinfo(host, *_args, **_kwargs):
        return [(socket.AF_INET, socket.SOCK_STREAM, 0, "", ("93.184.216.34", 0))]

    monkeypatch.setattr("app.utils.networking.socket.getaddrinfo", fake_getaddrinfo)
    assert validate_public_host("example.com") is None


def test_unresolvable_host_is_not_blocked_here(monkeypatch):
    def fake_getaddrinfo(host, *_args, **_kwargs):
        raise socket.gaierror("no records")

    monkeypatch.setattr("app.utils.networking.socket.getaddrinfo", fake_getaddrinfo)
    assert validate_public_host("no-such-host.invalid") is None


def test_host_strips_scheme_port_and_path():
    assert validate_public_host("http://127.0.0.1:8080/x") is not None
    assert validate_public_host("[::1]:80") is not None
    assert validate_public_host("https://8.8.8.8/anything?q=1") is None


def test_headers_module_refuses_private_literal_without_network():
    result = scan_headers_module("127.0.0.1")
    assert result.status == "error"
    assert "refusing" in result.details.get("error", "")


def test_ports_module_refuses_private_literal_without_network():
    result = scan_ports_module("127.0.0.1")
    assert result.status == "error"
    assert "refusing" in result.details.get("error", "")