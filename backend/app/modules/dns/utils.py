"""Shared helper functions for the DNS intelligence module."""

from typing import Any


def normalize_host(value: str) -> str:
    """Lowercase and strip a trailing dot from a hostname."""
    return value.strip().rstrip(".").lower()


def parse_mx_string(value: str) -> tuple[int, str] | None:
    """Parse an MX string like ``10 mail.example.com.`` into (preference, exchange)."""
    parts = value.strip().split()
    if len(parts) < 2:
        return None
    try:
        preference = int(parts[0])
    except ValueError:
        return None
    return preference, normalize_host(parts[1])


def has_spf(txt_records: list[str]) -> bool:
    """True when any TXT record declares an SPF policy."""
    return any("v=spf1" in record for record in txt_records)


def has_dmarc(txt_records: list[str]) -> bool:
    """True when any TXT record carries a DMARC policy declaration."""
    return any(record.lstrip().lower().startswith("v=dmarc1") for record in txt_records)


def has_duplicates(values: list[str]) -> bool:
    """True when a list contains case-insensitive duplicates."""
    normalized = [normalize_host(value) for value in values if value]
    return len(normalized) != len(set(normalized))


def min_ttl(ttls: list[int] | None) -> int | None:
    """Smallest observed TTL, or None when nothing was observed."""
    if not ttls:
        return None
    return min(ttls)


def as_string_list(value: Any) -> list[str]:
    """Coerce a DNS record payload into a list of strings."""
    if value is None:
        return []
    if isinstance(value, list):
        return [str(item).strip() for item in value if str(item).strip()]
    return [str(value).strip()]
