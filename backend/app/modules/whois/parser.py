"""Normalize provider-specific WHOIS output into a :class:`WhoisProfile`.

The python-whois library returns a loosely-typed object whose attributes
vary wildly between registries (dates as strings/datetimes/lists, name
servers as lists or dicts, fields missing entirely). This layer absorbs all
of that variance; it never raises and always produces a complete profile.
"""

from typing import Any

from app.modules.whois.models import WhoisProfile
from app.modules.whois.utils import as_datetime, clean_text, days_since, days_until, to_string_list


def _attr(data: Any, name: str) -> Any:
    return getattr(data, name, None)


def parse_whois(data: Any, domain: str) -> WhoisProfile:
    """Convert a raw WHOIS response object into a normalized profile."""
    creation = as_datetime(_attr(data, "creation_date"))
    updated = as_datetime(_attr(data, "updated_date"))
    expiration = as_datetime(_attr(data, "expiration_date"))

    name_servers = to_string_list(_attr(data, "name_servers"))

    return WhoisProfile(
        domain=domain.strip().lower(),
        registrar=clean_text(_attr(data, "registrar")),
        creation_date=_iso(creation),
        updated_date=_iso(updated),
        expiration_date=_iso(expiration),
        domain_age_days=days_since(creation),
        expires_in_days=days_until(expiration),
        organization=clean_text(_attr(data, "org") or _attr(data, "organization")),
        country=clean_text(_attr(data, "country")),
        dnssec=clean_text(_attr(data, "dnssec")),
        registrar_url=clean_text(_attr(data, "registrar_url") or _attr(data, "registrar_uri")),
        name_servers=name_servers,
        name_server_count=len(name_servers),
    )


def _iso(moment: Any) -> str | None:
    return moment.isoformat() if moment is not None else None
