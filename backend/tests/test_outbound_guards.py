"""Tests for the outbound-network safety guard (D1 hardening).

The guard prevents scan modules from contacting private/reserved networks,
both for IP literals and for hostnames whose DNS resolves to such addresses.
"""

import socket

import pytest

from app.modules.headers.scanner import scan_headers_module
from app.modules.ports.scanner import scan_ports_module
from app.modules.ssl.scanner import BlockedTargetError, fetch_tls
from app.modules.ssl.service import scan_ssl_module
from app.utils.networking import parse_host, validate_public_host

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


def test_ssl_module_refuses_private_ip_literals_without_network():
    for ip in ("10.0.0.1", "127.0.0.1", "169.254.169.254", "172.16.0.1", "192.168.1.1", "100.64.0.1", "0.0.0.0"):
        result = scan_ssl_module(ip)
        assert result.status == "error", f"expected {ip} to be refused"
        assert "refusing" in result.details.get("error", ""), f"no refusal reason for {ip}"


def test_ssl_module_refuses_non_public_hosts_without_network():
    for host in ("::1", "[::1]", "localhost", "localhost.localdomain", "local", "db.localhost"):
        result = scan_ssl_module(host)
        assert result.status == "error", f"expected {host} to be refused"
        assert result.details.get("error"), f"no refusal reason for {host}"


def test_ssl_fetch_tls_raises_blocked_for_private_literal():
    with pytest.raises(BlockedTargetError, match="refusing"):
        fetch_tls("127.0.0.1")


def test_ssl_fetch_tls_refuses_hostname_resolving_to_private(monkeypatch):
    def fake_getaddrinfo(host, *_args, **_kwargs):
        return [(socket.AF_INET, socket.SOCK_STREAM, 0, "", ("10.1.2.3", 0))]

    monkeypatch.setattr("app.utils.networking.socket.getaddrinfo", fake_getaddrinfo)
    with pytest.raises(BlockedTargetError, match="private"):
        fetch_tls("internal.example.internal")


def test_ssl_fetch_tls_proceeds_for_public_ip_literal_without_network(monkeypatch):
    def fake_attempt(hostname, timeout, verified):
        return "handshake-ok"

    monkeypatch.setattr("app.modules.ssl.scanner._attempt", fake_attempt)
    assert fetch_tls("8.8.8.8") == "handshake-ok"


def test_ssl_fetch_tls_proceeds_for_public_hostname(monkeypatch):
    def fake_getaddrinfo(host, *_args, **_kwargs):
        return [(socket.AF_INET, socket.SOCK_STREAM, 0, "", ("93.184.216.34", 0))]

    def fake_attempt(hostname, timeout, verified):
        return "handshake-ok"

    monkeypatch.setattr("app.utils.networking.socket.getaddrinfo", fake_getaddrinfo)
    monkeypatch.setattr("app.modules.ssl.scanner._attempt", fake_attempt)
    assert fetch_tls("example.com") == "handshake-ok"


def test_parse_host_extracts_destination_after_userinfo():
    assert parse_host("http://user:pass@example.com/") == "example.com"
    assert parse_host("https://user@127.0.0.1/") == "127.0.0.1"
    assert parse_host("http://admin@10.0.0.1:8080/x") == "10.0.0.1"
    assert parse_host("http://user@[::1]:443/") == "::1"
    assert parse_host("http://a@b@127.0.0.1/") == "127.0.0.1"
    assert parse_host("http://a%40b:secret@example.com/x") == "example.com"


def test_userinfo_cannot_disguise_private_destination():
    for target in (
        "http://user@127.0.0.1/",
        "https://attacker@10.0.0.1/",
        "http://user:pass@169.254.169.254/",
        "https://admin@192.168.1.1/",
        "http://user@100.64.0.1/",
        "http://user@[::1]/",
        "http://user@[fe80::1]/",
    ):
        reason = validate_public_host(target)
        assert reason is not None, f"expected {target} to be refused"
        assert "private" in reason or "reserved" in reason


def test_userinfo_public_destination_is_allowed():
    assert validate_public_host("http://user:pass@8.8.8.8/") is None
    assert validate_public_host("https://user@93.184.216.34/x") is None
    assert validate_public_host("http://user@[2606:4700:4700::1111]/") is None


def test_userinfo_hostname_resolving_to_private_is_refused(monkeypatch):
    def fake_getaddrinfo(host, *_args, **_kwargs):
        return [(socket.AF_INET, socket.SOCK_STREAM, 0, "", ("10.1.2.3", 0))]

    monkeypatch.setattr("app.utils.networking.socket.getaddrinfo", fake_getaddrinfo)
    reason = validate_public_host("http://attacker@internal.example.internal/")
    assert reason is not None
    assert "private" in reason


def test_headers_module_refuses_userinfo_private_destination_without_network():
    result = scan_headers_module("http://user:pass@127.0.0.1/")
    assert result.status == "error"
    assert "refusing" in result.details.get("error", "")


def test_ports_module_refuses_userinfo_private_destination_without_network():
    result = scan_ports_module("http://user:pass@127.0.0.1/")
    assert result.status == "error"
    assert "refusing" in result.details.get("error", "")


def test_ssl_module_refuses_userinfo_private_destination_without_network():
    result = scan_ssl_module("http://user:pass@127.0.0.1/")
    assert result.status == "error"
    assert "refusing" in result.details.get("error", "")


def test_normal_urls_without_userinfo_remain_unchanged():
    assert parse_host("https://example.com/path?q=1") == "example.com"
    assert parse_host("http://8.8.8.8:8080/") == "8.8.8.8"
    assert parse_host("[2606:4700:4700::1111]:443") == "2606:4700:4700::1111"
    assert parse_host("example.com") == "example.com"
    assert validate_public_host("https://example.com/") is None