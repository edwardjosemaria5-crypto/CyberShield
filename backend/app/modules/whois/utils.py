"""Shared helper functions for the WHOIS intelligence module."""

from datetime import datetime, timezone
from typing import Any


def now_utc() -> datetime:
    """Timezone-aware UTC now used for age/expiry math."""
    return datetime.now(timezone.utc)


def as_datetime(value: Any) -> datetime | None:
    """Best-effort coercion of a WHOIS date into a tz-aware UTC datetime.

    WHOIS providers return dates as ``datetime``, ``date``, strings in many
    formats, or lists thereof. Anything unparseable degrades to ``None``.
    """
    if not value:
        return None
    if isinstance(value, (list, tuple)):
        value = value[0] if value else None
        if not value:
            return None
    if isinstance(value, datetime):
        result = value
    elif isinstance(value, str):
        result = _parse_date_string(value)
        if result is None:
            return None
    else:
        # e.g. datetime.date, which python-whois occasionally returns
        try:
            result = datetime(value.year, value.month, value.day)
        except (AttributeError, TypeError, ValueError):
            return None
    if result.tzinfo is None:
        result = result.replace(tzinfo=timezone.utc)
    return result


def _parse_date_string(value: str) -> datetime | None:
    text = value.strip()
    if not text:
        return None
    try:
        return datetime.fromisoformat(text)
    except ValueError:
        pass
    for fmt in ("%Y-%m-%d", "%Y-%m-%d %H:%M:%S", "%Y/%m/%d", "%d-%b-%Y", "%d-%b-%y", "%d %b %Y", "%b %d %Y"):
        try:
            return datetime.strptime(text, fmt)
        except ValueError:
            continue
    return None


def days_since(moment: datetime | None) -> int | None:
    """Full days elapsed since ``moment`` (0 for future/unknown values)."""
    if moment is None:
        return None
    return max(0, (now_utc() - moment).days)


def days_until(moment: datetime | None) -> int | None:
    """Full days until ``moment``; negative when the moment has passed."""
    if moment is None:
        return None
    return (moment - now_utc()).days


def to_string_list(value: Any) -> list[str]:
    """Flatten a WHOIS field into a deduplicated list of strings.

    Handles lists, tuples, sets, single values, and the dict-shaped name
    server payloads some registries return (e.g. ``{"nserver": [...]}``).
    """
    if value is None:
        return []
    if isinstance(value, dict):
        flattened: list[str] = []
        for nested in value.values():
            flattened.extend(to_string_list(nested))
        return _dedupe(flattened)
    if isinstance(value, (list, tuple, set)):
        return _dedupe(str(item).strip() for item in value if item)
    return [str(value).strip()] if str(value).strip() else []


def _dedupe(items: Any) -> list[str]:
    return list(dict.fromkeys(items))


def clean_text(value: Any) -> str | None:
    """Strip a WHOIS text field; None for empty or list-wrapped values."""
    if value is None:
        return None
    if isinstance(value, (list, tuple)):
        value = value[0] if value else None
        if value is None:
            return None
    text = str(value).strip()
    return text or None
