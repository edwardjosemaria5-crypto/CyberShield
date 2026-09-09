"""Tests for the Phase 4 bounded in-memory infrastructure provider cache.

Covers the required behaviors:
- cache miss → adapter called once, validated success cached
- cache hit → adapter not called again for the same validated IP
- TTL expiry (deterministic via injected monotonic time source) → fresh lookup
- transient failures are NEVER cached (typed UnavailableData, all reasons)
- invalid / private / non-canonical targets bypass the cache entirely — a hit
  can never bypass parse_host()/resolve_public_host() validation
- a raw URL / hostname / userinfo string can never become a cache key
- IPv6 literals are cached and re-served correctly
- hard size bound with deterministic LRU eviction
- thread-safe concurrent get/put (no deadlock, no corruption, bound held)
- mutation isolation: callers can never corrupt the cached value via the
  deep copies get() returns
"""

import socket
import threading

import pytest

from app.modules.infrastructure.adapter import (
    InfrastructureAdapter,
    InfrastructureData,
    UnavailableData,
)
from app.modules.infrastructure.cache import InfrastructureCache
from app.modules.infrastructure.scanner import scan_infrastructure_module

EXAMPLE_IP = "93.184.216.34"
EXAMPLE_IPV6 = "2606:2800:220:1:248:1893:25c8:1946"


def build_data(ip=EXAMPLE_IP, asn="AS15133", country="United States"):
    return InfrastructureData(
        ip=ip,
        asn=asn,
        asn_organization="EdgeCast Networks, Inc.",
        isp="MCI Communications Services",
        hosting_provider="EdgeCast Networks, Inc.",
        network="93.184.216.0/24",
        reverse_dns="edgecastcdn.net",
        country=country,
        country_code="US",
        region="California",
        source="fake",
    )


class CountingAdapter(InfrastructureAdapter):
    """Deterministic adapter stub; counts every lookup it receives."""

    provider = "fake"

    def __init__(self, results=None):
        super().__init__()
        self.results = dict(results or {})
        self.calls: list[str] = []

    @property
    def is_configurable(self):
        return True

    def lookup(self, ip_address):
        self.calls.append(ip_address)
        if ip_address in self.results:
            return self.results[ip_address]
        return UnavailableData(
            provider=self.provider, reason="no_analysis", detail="no row for ip"
        )


class FakeClock:
    """Deterministic monotonic time source for TTL tests."""

    def __init__(self, start=0.0):
        self._now = float(start)

    def __call__(self):
        return self._now

    def advance(self, seconds):
        self._now += seconds


def _monkey_dns(monkeypatch, ips):
    """Pin ``socket.getaddrinfo`` in the networking module to a fixed list."""

    def fake_getaddrinfo(host, *_args, **_kwargs):
        if ips is None:
            raise socket.gaierror("no such host")
        return [(socket.AF_INET, socket.SOCK_STREAM, 0, "", (ip, 0)) for ip in ips]

    monkeypatch.setattr("app.utils.networking.socket.getaddrinfo", fake_getaddrinfo)


# ============================================================ 1. miss → hit

def test_cache_miss_calls_adapter_once_then_caches(monkeypatch):
    """First scan: cache miss → one adapter call; the validated profile is cached."""
    _monkey_dns(monkeypatch, [EXAMPLE_IP])
    cache = InfrastructureCache(ttl_seconds=1000.0, time_source=FakeClock())
    adapter = CountingAdapter({EXAMPLE_IP: build_data()})

    result = scan_infrastructure_module("example.com", adapter=adapter, cache=cache)

    assert result.details["infrastructure"]["status"] == "available"
    assert adapter.calls == [EXAMPLE_IP]
    assert len(cache) == 1
    assert cache.get(EXAMPLE_IP) is not None


def test_cache_hit_skips_adapter_call(monkeypatch):
    """Second scan for the same validated public IP: served from cache, zero
    provider contact."""
    _monkey_dns(monkeypatch, [EXAMPLE_IP])
    cache = InfrastructureCache(ttl_seconds=1000.0, time_source=FakeClock())
    adapter = CountingAdapter({EXAMPLE_IP: build_data()})

    first = scan_infrastructure_module("example.com", adapter=adapter, cache=cache)
    second = scan_infrastructure_module("example.com", adapter=adapter, cache=cache)

    assert adapter.calls == [EXAMPLE_IP], "provider must not be contacted again"
    assert second.details["infrastructure"]["asn"] == first.details["infrastructure"]["asn"]
    assert second.details["infrastructure"]["status"] == "available"


def test_cache_hit_service_across_target_spellings(monkeypatch):
    """Different raw spellings FQDN-only, but the same resolved public IP reuse
    the same cache entry — the key is the IP literal, never the input string."""
    _monkey_dns(monkeypatch, [EXAMPLE_IP])
    cache = InfrastructureCache(ttl_seconds=1000.0, time_source=FakeClock())
    adapter = CountingAdapter({EXAMPLE_IP: build_data()})

    scan_infrastructure_module("example.com", adapter=adapter, cache=cache)
    scan_infrastructure_module("www.example.com", adapter=adapter, cache=cache)

    assert adapter.calls == [EXAMPLE_IP]


# ============================================================ 2. TTL expiry

def test_ttl_expiry_triggers_fresh_lookup(monkeypatch):
    """Expired entries are never served and trigger a fresh provider lookup."""
    _monkey_dns(monkeypatch, [EXAMPLE_IP])
    clock = FakeClock()
    cache = InfrastructureCache(ttl_seconds=100.0, time_source=clock)
    adapter = CountingAdapter({EXAMPLE_IP: build_data()})

    scan_infrastructure_module("example.com", adapter=adapter, cache=cache)
    clock.advance(50.0)
    scan_infrastructure_module("example.com", adapter=adapter, cache=cache)
    assert adapter.calls == [EXAMPLE_IP], "entry is still live at t=50"

    clock.advance(60.0)  # t=110 ≥ 100 → expired
    scan_infrastructure_module("example.com", adapter=adapter, cache=cache)
    assert adapter.calls == [EXAMPLE_IP, EXAMPLE_IP]
    assert len(cache) == 1, "refreshed entry replaces the expired one"


# ============================================================ 3. failures never cached

@pytest.mark.parametrize(
    "reason",
    ["timeout", "network", "rate_limited", "server_error", "bad_response", "unknown"],
)
def test_failure_data_is_never_cached(reason):
    """UnavailableData of every canonical reason must never enter the cache."""
    cache = InfrastructureCache(ttl_seconds=1000.0, time_source=FakeClock())

    cache.put(EXAMPLE_IP, UnavailableData(reason=reason, detail="transient"))

    assert len(cache) == 0
    assert cache.get(EXAMPLE_IP) is None


def test_transient_failure_not_sticky_across_scans(monkeypatch):
    """A transient timeout is not sticky: the next scan contacts the provider again."""
    _monkey_dns(monkeypatch, [EXAMPLE_IP])
    cache = InfrastructureCache(ttl_seconds=1000.0, time_source=FakeClock())
    adapter = CountingAdapter(
        {EXAMPLE_IP: UnavailableData(reason="timeout", detail="provider is slow")}
    )

    for _ in range(2):
        result = scan_infrastructure_module("example.com", adapter=adapter, cache=cache)
        assert result.details["infrastructure"]["reason"] == "timeout"

    assert adapter.calls == [EXAMPLE_IP, EXAMPLE_IP]
    assert len(cache) == 0


# ============================================================ 4. invalid targets bypass cache

@pytest.mark.parametrize("target", ["127.0.0.1", "localhost", "[::1]", "2130706433"])
def test_invalid_targets_never_touch_cache_or_provider(target):
    """Pre-warmed cache must NOT be served for private/reserved/non-canonical
    targets — validation runs before the cache is ever consulted."""
    cache = InfrastructureCache(ttl_seconds=1000.0, time_source=FakeClock())
    cache.put(EXAMPLE_IP, build_data())  # warm an unrelated entry
    adapter = CountingAdapter({EXAMPLE_IP: build_data()})

    result = scan_infrastructure_module(target, adapter=adapter, cache=cache)

    assert result.details["infrastructure"]["status"] == "unavailable"
    assert result.details["infrastructure"]["reason"] == "invalid_target"
    assert adapter.calls == [], "provider must not be contacted for an invalid target"
    assert cache.get(EXAMPLE_IP) is not None, "cache entry should be untouched"
    assert not any(
        cache.get(target) is not None for target in ["127.0.0.1", "localhost", "::1"]
    )


def test_mixed_dns_refused_before_cache_read(monkeypatch):
    """Public+private DNS answers are refused by the shared all-or-nothing
    policy; the permissive cache path never gets a chance to answer."""
    _monkey_dns(monkeypatch, [EXAMPLE_IP, "10.0.0.1"])
    cache = InfrastructureCache(ttl_seconds=1000.0, time_source=FakeClock())
    cache.put(EXAMPLE_IP, build_data())
    adapter = CountingAdapter({EXAMPLE_IP: build_data()})

    result = scan_infrastructure_module("example.com", adapter=adapter, cache=cache)

    assert result.details["infrastructure"]["reason"] == "invalid_target"
    assert adapter.calls == []


# ============================================================ 5. raw URL never a key

def test_raw_url_never_becomes_cache_key(monkeypatch):
    """The cache key is the validated IP literal — the raw URL, hostname and
    userinfo forms can never be stored or served as keys."""
    _monkey_dns(monkeypatch, [EXAMPLE_IP])
    cache = InfrastructureCache(ttl_seconds=1000.0, time_source=FakeClock())
    adapter = CountingAdapter({EXAMPLE_IP: build_data()})

    raw_target = "https://user:pass@example.com/suspicious/path?x=1"
    scan_infrastructure_module(raw_target, adapter=adapter, cache=cache)

    # Positive: only the validated IP literal is a live key.
    assert cache.get(EXAMPLE_IP) is not None
    assert len(cache) == 1
    for forbidden in [
        raw_target,
        "https://user:pass@example.com/suspicious/path?x=1",
        "example.com",
        "https://example.com",
        "user:pass@example.com",
        "user:pass",
    ]:
        assert cache.get(forbidden) is None, f"forbidden cache key: {forbidden!r}"

    # A different raw spelling of the same IP hits the same cached entry.
    scan_infrastructure_module("http://example.com/other/y=2", adapter=adapter, cache=cache)
    assert adapter.calls == [EXAMPLE_IP], "second spelling must be a cache hit"


# ============================================================ 6. IPv6 caching

def test_ipv6_literal_cached_and_hit(monkeypatch):
    _monkey_dns(monkeypatch, [EXAMPLE_IPV6])
    cache = InfrastructureCache(ttl_seconds=1000.0, time_source=FakeClock())
    adapter = CountingAdapter(
        {EXAMPLE_IPV6: InfrastructureData(ip=EXAMPLE_IPV6, asn="AS15133", source="fake")}
    )

    scan_infrastructure_module("example.com", adapter=adapter, cache=cache)
    assert cache.get(EXAMPLE_IPV6) is not None
    assert adapter.calls == [EXAMPLE_IPV6]

    scan_infrastructure_module("example.com", adapter=adapter, cache=cache)
    assert adapter.calls == [EXAMPLE_IPV6], "IPv6 entry must be a cache hit"


# ============================================================ 7. size bound + LRU eviction

def test_cache_size_bound_with_deterministic_lru_eviction():
    cache = InfrastructureCache(ttl_seconds=1000.0, max_entries=3, time_source=FakeClock())
    ips = ["192.0.2.1", "192.0.2.2", "192.0.2.3", "192.0.2.4"]

    for ip in ips:
        cache.put(ip, build_data(ip=ip))

    assert len(cache) == 3
    assert cache.get(ips[0]) is None, "oldest entry must be evicted"
    assert all(cache.get(ip) is not None for ip in ips[1:])


def test_lru_refresh_changes_eviction_order():
    cache = InfrastructureCache(ttl_seconds=1000.0, max_entries=3, time_source=FakeClock())
    ips = ["192.0.2.1", "192.0.2.2", "192.0.2.3"]
    for ip in ips:
        cache.put(ip, build_data(ip=ip))

    cache.get(ips[0])  # refresh recency of 192.0.2.1
    cache.put("192.0.2.4", build_data(ip="192.0.2.4"))  # evicts least-recent 192.0.2.2

    assert len(cache) == 3
    assert cache.get(ips[0]) is not None, "refreshed entry must be retained"
    assert cache.get(ips[1]) is None, "least-recently-used entry must be evicted"
    assert cache.get(ips[2]) is not None


# ============================================================ 8. concurrency

def test_concurrent_access_is_safe():
    cache = InfrastructureCache(
        ttl_seconds=1000.0, max_entries=64, time_source=FakeClock()
    )
    errors = []

    def worker(start):
        try:
            for i in range(80):
                ip = f"203.0.113.{start + i}"
                cache.put(ip, build_data(ip=ip, asn="ASTEST"))
                back = cache.get(ip)
                if back is not None:
                    assert back.asn == "ASTEST"
        except Exception as exc:  # noqa: BLE001 - collect for the assertion below
            errors.append(exc)

    threads = [
        threading.Thread(target=worker, args=(1,)),
        threading.Thread(target=worker, args=(200,)),
        threading.Thread(target=worker, args=(400,)),
        threading.Thread(target=worker, args=(600,)),
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert errors == [], f"concurrent cache access raised: {errors}"
    assert len(cache) <= 64
    assert len(cache) >= 0


# ============================================================ 9. mutation isolation

def test_returned_deep_copy_cannot_corrupt_cache():
    cache = InfrastructureCache(ttl_seconds=1000.0, time_source=FakeClock())
    cache.put(EXAMPLE_IP, build_data(asn="AS15133"))

    poisoned = cache.get(EXAMPLE_IP)
    assert poisoned is not None
    poisoned.asn = "AS-EVIL"
    poisoned.country = "Attackerland"

    fresh = cache.get(EXAMPLE_IP)
    assert fresh.asn == "AS15133", "cached value must be pristine"
    assert fresh.country == "United States"


def test_scan_does_not_mutate_cached_entry(monkeypatch):
    _monkey_dns(monkeypatch, [EXAMPLE_IP])
    cache = InfrastructureCache(ttl_seconds=1000.0, time_source=FakeClock())
    adapter = CountingAdapter({EXAMPLE_IP: build_data()})

    first = scan_infrastructure_module("example.com", adapter=adapter, cache=cache)
    first.details["infrastructure"]["asn"] = "AS-EVIL"

    second = scan_infrastructure_module("example.com", adapter=adapter, cache=cache)
    assert second.details["infrastructure"]["asn"] == "AS15133", "cache must be intact"