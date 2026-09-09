"""In-memory, bounded, TTL cache for validated infrastructure provider data.

Phase 4 hardening for the informational infrastructure module.

Security properties:

- The cache stores ONLY validated :class:`InfrastructureData` — a provider
  lookup that produced a typed success. Every failure state (timeout,
  network, rate_limited, server_error, bad_response, unknown, ...) is never
  cached, so transient provider problems cannot become sticky.
- Keys are the validated public IP literals produced upstream by
  ``resolve_public_host()`` (IPv6 already compressed). The cache is used
  ONLY AFTER target validation inside the scanner, so a hit can never
  bypass ``parse_host()`` / ``resolve_public_host()`` and can never return
  data for private/reserved attributes or raw-input targets.
- Expiry uses a monotonic clock (``time.monotonic`` by default), so
  wall-clock jumps cannot stall or prematurely clear entries.
- The store is a hard-bounded ``OrderedDict`` with LRU eviction: repeated
  attacker-controlled IPs cannot grow memory without limit.
- Access is guarded by a :class:`threading.Lock` because the scanner runs
  modules concurrently.
- Returned values are deep copies, so a caller can never mutate the cached
  object and poison future cache reads.
- Every operation is best-effort: a defective cache degrades to a direct
  provider call — it can never fail or alter a scan.
"""

import logging
import threading
import time
from collections import OrderedDict

from app.modules.infrastructure.adapter import InfrastructureData, UnavailableData

logger = logging.getLogger("cybershield.infrastructure.cache")

#: Hard cap on cached IP profiles. Deterministic LRU eviction keeps memory
#: bounded even under abusive scan volume; entries are a few hundred bytes,
#: so the worst case stays in the tens of kilobytes. No attacker can grow
#: the store beyond this bound without owner restart.
MAX_CACHE_ENTRIES = 1024


class InfrastructureCache:
    """Thread-safe, bounded, TTL cache keyed by a validated IP literal.

    ``time_source`` is injectable for deterministic tests; it must return
    the current time in monotonic seconds.
    """

    def __init__(
        self,
        ttl_seconds: float = 86400.0,
        max_entries: int = MAX_CACHE_ENTRIES,
        time_source=time.monotonic,
    ) -> None:
        self._ttl_seconds = float(ttl_seconds)
        self._max_entries = max(1, int(max_entries))
        self._now = time_source
        self._lock = threading.Lock()
        self._data: OrderedDict[str, tuple[float, InfrastructureData]] = OrderedDict()

    def get(self, ip_literal: str) -> InfrastructureData | None:
        """Return a fresh deep copy when ``ip_literal`` has a live entry.

        Expired entries are dropped (never returned) and trigger a fresh
        provider lookup by the caller. Best-effort: any internal defect
        degrades to ``None`` (a cache miss), which the caller resolves with
        a normal provider lookup.
        """
        try:
            with self._lock:
                entry = self._data.get(ip_literal)
                if entry is None:
                    return None
                expires_at, data = entry
                if self._now() >= expires_at:
                    self._data.pop(ip_literal, None)
                    logger.debug("Infrastructure cache expired for %s", ip_literal)
                    return None
                self._data.move_to_end(ip_literal)
                logger.debug("Infrastructure cache hit for %s", ip_literal)
                return data.model_copy(deep=True)
        except Exception:  # noqa: BLE001 - cache is best-effort by contract
            logger.warning(
                "Infrastructure cache read failed for %s; falling back to provider",
                ip_literal,
            )
            return None

    def put(self, ip_literal: str, data: InfrastructureData | UnavailableData) -> None:
        """Cache a validated success only; failures are never made sticky.

        Stores a deep snapshot so later caller mutations cannot corrupt the
        cached entry. When full, the least-recently-used entry is evicted
        deterministically. Best-effort: a failing write is ignored and the
        caller simply performs the next lookup live.
        """
        if not isinstance(data, InfrastructureData):
            return
        try:
            snapshot = data.model_copy(deep=True)
            with self._lock:
                self._data.pop(ip_literal, None)
                self._data[ip_literal] = (self._now() + self._ttl_seconds, snapshot)
                while len(self._data) > self._max_entries:
                    self._data.popitem(last=False)
                logger.debug("Infrastructure cache stored for %s", ip_literal)
        except Exception:  # noqa: BLE001 - cache is best-effort by contract
            logger.warning("Infrastructure cache write failed for %s", ip_literal)

    def __len__(self) -> int:
        try:
            with self._lock:
                return len(self._data)
        except Exception:  # noqa: BLE001 - cache is best-effort by contract
            return 0