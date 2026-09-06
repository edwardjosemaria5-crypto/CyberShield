"""Tests for the outbound-network safety guard (D1 hardening).

The guard prevents scan modules from contacting private/reserved networks,
both for IP literals and for hostnames whose DNS resolves to such addresses.
"""

import socket

import pytest

from app.modules.headers.scanner import (
    BlockedTargetError,
    _PinnedAdapter,
    _follow_redirects_safely,
    scan_headers_module,
)
from app.modules.ports.scanner import scan_ports_module
from app.modules.ssl.scanner import BlockedTargetError as SslBlockedTargetError, fetch_tls
from app.modules.ssl.service import scan_ssl_module
from app.utils.networking import (
    ResolvedTarget,
    parse_host,
    resolve_public_host,
    validate_public_host,
)

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
    with pytest.raises(SslBlockedTargetError, match="refusing"):
        fetch_tls("127.0.0.1")


def test_ssl_fetch_tls_refuses_hostname_resolving_to_private(monkeypatch):
    def fake_getaddrinfo(host, *_args, **_kwargs):
        return [(socket.AF_INET, socket.SOCK_STREAM, 0, "", ("10.1.2.3", 0))]

    monkeypatch.setattr("app.utils.networking.socket.getaddrinfo", fake_getaddrinfo)
    with pytest.raises(SslBlockedTargetError, match="private"):
        fetch_tls("internal.example.internal")


def test_ssl_fetch_tls_proceeds_for_public_ip_literal_without_network(monkeypatch):
    captured = {}

    def fake_attempt(hostname, addresses, timeout, verified):
        captured["hostname"] = hostname
        captured["addresses"] = addresses
        return "handshake-ok"

    monkeypatch.setattr("app.modules.ssl.scanner._attempt", fake_attempt)
    assert fetch_tls("8.8.8.8") == "handshake-ok"
    assert captured["hostname"] == "8.8.8.8"
    assert captured["addresses"] == ("8.8.8.8",)


def test_ssl_fetch_tls_proceeds_for_public_hostname(monkeypatch):
    def fake_getaddrinfo(host, *_args, **_kwargs):
        return [(socket.AF_INET, socket.SOCK_STREAM, 0, "", ("93.184.216.34", 0))]

    captured = {}

    def fake_attempt(hostname, addresses, timeout, verified):
        captured["hostname"] = hostname
        captured["addresses"] = addresses
        return "handshake-ok"

    monkeypatch.setattr("app.utils.networking.socket.getaddrinfo", fake_getaddrinfo)
    monkeypatch.setattr("app.modules.ssl.scanner._attempt", fake_attempt)
    assert fetch_tls("example.com") == "handshake-ok"
    # The hostname is preserved (SNI / cert), but the connect address is the
    # pinned public IP literal — never the hostname (DNS-rebinding/TOCTOU fix).
    assert captured["hostname"] == "example.com"
    assert captured["addresses"] == ("93.184.216.34",)


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


# ---------------------------------------------------------------------------
# DNS-rebinding / TOCTOU: resolve_public_host (single authoritative resolution)
# ---------------------------------------------------------------------------


def _resolve(monkeypatch, infos):
    def fake_getaddrinfo(host, *_args, **_kwargs):
        if infos == "gaierror":
            raise socket.gaierror("no records")
        return infos

    monkeypatch.setattr("app.utils.networking.socket.getaddrinfo", fake_getaddrinfo)


def test_resolve_returns_pinned_public_literals(monkeypatch):
    infos = [
        (socket.AF_INET, socket.SOCK_STREAM, 0, "", ("93.184.216.34", 0)),
        (socket.AF_INET6, socket.SOCK_STREAM, 0, "", ("2606:4700:4700::1111", 0, 0, 0)),
    ]
    _resolve(monkeypatch, infos)
    target, reason = resolve_public_host("example.com")
    assert reason is None
    assert target is not None
    assert target.host == "example.com"
    assert "93.184.216.34" in target.addresses
    assert "2606:4700:4700::1111" in target.addresses
    assert target.ipv4 == ("93.184.216.34",)
    assert target.ipv6 == ("2606:4700:4700::1111",)


def test_resolve_pins_ipv4_before_ipv6_in_ordering():
    target, _ = resolve_public_host("93.184.216.34")
    assert target is not None
    assert target.addresses == ("93.184.216.34",)


def test_resolve_refuses_if_any_answer_is_private(monkeypatch):
    infos = [
        (socket.AF_INET, socket.SOCK_STREAM, 0, "", ("93.184.216.34", 0)),
        (socket.AF_INET, socket.SOCK_STREAM, 0, "", ("10.0.0.1", 0)),
    ]
    _resolve(monkeypatch, infos)
    target, reason = resolve_public_host("rebinding.example.internal")
    assert target is None
    assert "private" in reason


def test_resolve_refuses_if_any_answer_is_private_ipv6(monkeypatch):
    infos = [
        (socket.AF_INET, socket.SOCK_STREAM, 0, "", ("93.184.216.34", 0)),
        (socket.AF_INET6, socket.SOCK_STREAM, 0, "", ("::1", 0, 0, 0)),
    ]
    _resolve(monkeypatch, infos)
    target, reason = resolve_public_host("rebinding.example.internal")
    assert target is None
    assert "private" in reason or "reserved" in reason


def test_resolve_allows_multiple_public_answers_without_dedup_loss(monkeypatch):
    infos = [
        (socket.AF_INET, socket.SOCK_STREAM, 0, "", ("93.184.216.34", 0)),
        (socket.AF_INET, socket.SOCK_STREAM, 0, "", ("93.184.216.35", 0)),
    ]
    _resolve(monkeypatch, infos)
    target, reason = resolve_public_host("cdn.example.com")
    assert reason is None
    assert target is not None
    assert set(target.addresses) == {"93.184.216.34", "93.184.216.35"}


def test_resolve_unresolvable_host_returns_none_none(monkeypatch):
    _resolve(monkeypatch, "gaierror")
    target, reason = resolve_public_host("no-such-host.invalid")
    assert target is None
    assert reason is None


def test_resolve_private_literals_are_refused():
    for ip in _PRIVATE_IP_LITERALS:
        target, reason = resolve_public_host(ip)
        assert target is None, f"expected {ip} to be refused"
        assert "private" in reason or "reserved" in reason


def test_resolve_public_literals_are_allowed():
    for ip in _PUBLIC_IP_LITERALS:
        target, reason = resolve_public_host(ip)
        assert reason is None, f"expected {ip} to be allowed"
        assert target is not None
        assert target.addresses == (ip if ":" not in ip else target.ipv6[0],)


def test_resolve_refuses_private_hostname_without_resolution():
    for name in ("localhost", "db.localhost", "local"):
        target, reason = resolve_public_host(name)
        assert target is None
        assert reason is not None


def test_resolve_refuses_non_canonical_numeric_hosts():
    for host in ("2130706433", "0x7f000001", "0177.0.0.1", "127.1", "010.000.000.001"):
        target, reason = resolve_public_host(host)
        assert target is None, f"expected {host} to be refused"
        assert "non-canonical" in reason


def test_resolve_refuses_non_canonical_numeric_via_userinfo():
    target, reason = resolve_public_host("http://user:pass@2130706433:443/")
    assert target is None
    assert "non-canonical" in reason


def test_resolve_strips_userinfo_and_scheme():
    target, reason = resolve_public_host("https://user@93.184.216.34/x")
    assert reason is None
    assert target is not None
    assert target.addresses == ("93.184.216.34",)


# ---------------------------------------------------------------------------
# Headers HTTP adapter: connect to pinned IP, keep hostname for SNI/Host
# ---------------------------------------------------------------------------


class _FakePool:
    """Captures connection kwargs and yields a minimal urllib3-like response."""

    def __init__(self, **kwargs):
        self.kwargs = kwargs
        self.calls = []

    def urlopen(self, *_args, **_kwargs):
        self.calls.append(_kwargs)
        return _FakeResponse()

    def close(self):
        pass


class _FakeResponse:
    status = 200
    reason = "OK"

    def __init__(self):
        self._headers = {"X-Test": "1"}
        self.headers = dict(self._headers)

    def getheader(self, name, default=None):
        return self._headers.get(name, default)

    def getheaders(self):
        return list(self._headers.items())

    def read(self, *a, **kw):
        return b""


def test_headers_adapter_pins_ip_and_keeps_sni_hostname(monkeypatch):
    import requests

    captured = {}

    class FakePool(_FakePool):
        def __init__(self, **kwargs):
            super().__init__(**kwargs)
            captured["kwargs"] = kwargs

    monkeypatch.setattr(
        "app.modules.headers.scanner.resolve_public_host",
        lambda url: (ResolvedTarget("example.com", ("93.184.216.34",)), None),
    )
    monkeypatch.setattr("app.modules.headers.scanner.HTTPSConnectionPool", FakePool)
    monkeypatch.setattr("app.modules.headers.scanner.HTTPConnectionPool", FakePool)

    adapter = _PinnedAdapter()
    request = requests.Request("GET", "https://example.com/headers").prepare()
    response = adapter.send(request)

    assert captured["kwargs"]["host"] == "93.184.216.34"
    assert captured["kwargs"]["server_hostname"] == "example.com"
    assert captured["kwargs"]["assert_hostname"] == "example.com"
    assert captured["kwargs"]["cert_reqs"] == "CERT_REQUIRED"
    assert response.status_code == 200


def test_headers_adapter_refuses_private_host(monkeypatch):
    import requests

    monkeypatch.setattr(
        "app.modules.headers.scanner.resolve_public_host",
        lambda url: (None, "Target '127.0.0.1' is private/reserved; refusing."),
    )
    adapter = _PinnedAdapter()
    request = requests.Request("GET", "https://127.0.0.1/").prepare()
    with pytest.raises(BlockedTargetError, match="private"):
        adapter.send(request)


def test_headers_redirect_to_private_host_is_refused(monkeypatch):
    monkeypatch.setattr(
        "app.modules.headers.scanner.resolve_public_host",
        lambda url: (None, "Target '10.0.0.1' is private/reserved; refusing."),
    )
    with pytest.raises(BlockedTargetError, match="private"):
        _follow_redirects_safely("https://example.com/")


# ---------------------------------------------------------------------------
# Phase 2A fixes: ports pinning, forced Host header, redirect cap revalidation
# ---------------------------------------------------------------------------


def test_ports_scanner_connects_only_to_pinned_literals(monkeypatch):
    captured = []

    def fake_check_port(address, port, timeout=None):
        captured.append(address)
        return None

    monkeypatch.setattr(
        "app.modules.ports.scanner.resolve_public_host",
        lambda host: (ResolvedTarget("evil.example", ("93.184.216.34", "2606:4700:4700::1111")), None),
    )
    monkeypatch.setattr("app.modules.ports.scanner._check_port", fake_check_port)

    result = scan_ports_module("evil.example")

    assert set(captured) == {"93.184.216.34", "2606:4700:4700::1111"}
    assert "evil.example" not in captured
    assert result.status == "ok"


def test_headers_adapter_keeps_validated_host_in_host_header(monkeypatch):
    import requests

    captured = {}

    class FakePool(_FakePool):
        def __init__(self, **kwargs):
            super().__init__(**kwargs)
            captured["pool_kwargs"] = kwargs

        def urlopen(self, *_args, **_kwargs):
            captured["urlopen_headers"] = _kwargs.get("headers") or {}
            return _FakeResponse()

    monkeypatch.setattr(
        "app.modules.headers.scanner.resolve_public_host",
        lambda url: (ResolvedTarget("example.com", ("93.184.216.34",)), None),
    )
    monkeypatch.setattr("app.modules.headers.scanner.HTTPSConnectionPool", FakePool)
    monkeypatch.setattr("app.modules.headers.scanner.HTTPConnectionPool", FakePool)

    adapter = _PinnedAdapter()
    request = requests.Request("GET", "https://example.com/readme").prepare()
    adapter.send(request)

    assert captured["pool_kwargs"]["host"] == "93.184.216.34"
    assert captured["urlopen_headers"]["Host"] == "example.com"


def test_headers_adapter_ignores_caller_host_header(monkeypatch):
    import requests

    captured = {}

    class FakePool(_FakePool):
        def urlopen(self, *_args, **_kwargs):
            captured["host"] = (_kwargs.get("headers") or {}).get("Host")
            return _FakeResponse()

    monkeypatch.setattr(
        "app.modules.headers.scanner.resolve_public_host",
        lambda url: (ResolvedTarget("example.com", ("93.184.216.34",)), None),
    )
    monkeypatch.setattr("app.modules.headers.scanner.HTTPSConnectionPool", FakePool)
    monkeypatch.setattr("app.modules.headers.scanner.HTTPConnectionPool", FakePool)

    adapter = _PinnedAdapter()
    request = requests.Request(
        "GET", "https://example.com/", headers={"Host": "attacker.invalid"}
    ).prepare()
    adapter.send(request)

    assert captured["host"] == "example.com"


class _RedirectResponse:
    reason = "OK"

    def __init__(self, status, location=None):
        self.status = status
        self._headers = {"X-Test": "1"}
        if location:
            self._headers["location"] = location
        self.headers = dict(self._headers)

    def getheader(self, name, default=None):
        return self._headers.get(name, default)

    def getheaders(self):
        return list(self._headers.items())

    def read(self, *a, **kw):
        return b""


def _resolve_host(hosts):
    def resolve(url):
        host = url.split("://", 1)[1].split("/", 1)[0].lower()
        return ResolvedTarget(host, hosts[host]), None

    return resolve


def _redirect_pool_factory(chain, pool_hosts, hop_hosts):
    class Pool(_FakePool):
        def __init__(self, **kwargs):
            super().__init__(**kwargs)
            pool_hosts.append(kwargs["host"])

        def urlopen(self, *_args, **_kwargs):
            self.calls.append(_kwargs)
            hop_hosts.append((_kwargs.get("headers") or {}).get("Host"))
            location = chain.get(self.kwargs["host"])
            return _RedirectResponse(302 if location else 200, location)

    return Pool


def test_headers_redirect_chain_revalidates_and_repins_every_hop(monkeypatch):
    pool_hosts = []
    hop_hosts = []
    chain = {
        "1.1.1.1": "https://b.example/howdy",
        "2.2.2.2": "https://c.example/howdy",
        "3.3.3.3": None,
    }
    hosts = {
        "a.example": ("1.1.1.1",),
        "b.example": ("2.2.2.2",),
        "c.example": ("3.3.3.3",),
    }

    monkeypatch.setattr("app.modules.headers.scanner.resolve_public_host", _resolve_host(hosts))
    Pool = _redirect_pool_factory(chain, pool_hosts, hop_hosts)
    monkeypatch.setattr("app.modules.headers.scanner.HTTPSConnectionPool", Pool)
    monkeypatch.setattr("app.modules.headers.scanner.HTTPConnectionPool", Pool)

    response = _follow_redirects_safely("https://a.example/")

    assert response.status_code == 200
    assert pool_hosts == ["1.1.1.1", "2.2.2.2", "3.3.3.3"]
    assert hop_hosts == ["a.example", "b.example", "c.example"]


def test_headers_redirect_chain_stops_after_max_hops(monkeypatch):
    import requests

    pool_hosts = []
    hop_hosts = []
    chain = {
        "1.1.1.1": "https://b.example/howdy",
        "2.2.2.2": "https://c.example/howdy",
        "3.3.3.3": "https://d.example/howdy",
        "4.4.4.4": "https://e.example/howdy",
        "5.5.5.5": "https://a.example/again",
    }
    hosts = {
        "a.example": ("1.1.1.1",),
        "b.example": ("2.2.2.2",),
        "c.example": ("3.3.3.3",),
        "d.example": ("4.4.4.4",),
        "e.example": ("5.5.5.5",),
    }

    monkeypatch.setattr("app.modules.headers.scanner.resolve_public_host", _resolve_host(hosts))
    Pool = _redirect_pool_factory(chain, pool_hosts, hop_hosts)
    monkeypatch.setattr("app.modules.headers.scanner.HTTPSConnectionPool", Pool)
    monkeypatch.setattr("app.modules.headers.scanner.HTTPConnectionPool", Pool)

    with pytest.raises(requests.TooManyRedirects):
        _follow_redirects_safely("https://a.example/")

    assert pool_hosts == ["1.1.1.1", "2.2.2.2", "3.3.3.3", "4.4.4.4"]
    assert len(pool_hosts) == 4


def test_headers_redirect_to_private_host_refused_after_public_first_hop(monkeypatch):
    calls = []

    def resolve(url):
        if "private.example" in url:
            return None, "Target 'private.example' resolves to a private/reserved address; refusing."
        return ResolvedTarget("example.com", ("93.184.216.34",)), None

    class Pool(_FakePool):
        def __init__(self, **kwargs):
            super().__init__(**kwargs)
            calls.append(kwargs)

        def urlopen(self, *_args, **_kwargs):
            return _RedirectResponse(302, "https://private.example/steal")

    monkeypatch.setattr("app.modules.headers.scanner.resolve_public_host", resolve)
    monkeypatch.setattr("app.modules.headers.scanner.HTTPSConnectionPool", Pool)
    monkeypatch.setattr("app.modules.headers.scanner.HTTPConnectionPool", Pool)

    with pytest.raises(BlockedTargetError, match="private"):
        _follow_redirects_safely("https://example.com/")

    assert len(calls) == 1