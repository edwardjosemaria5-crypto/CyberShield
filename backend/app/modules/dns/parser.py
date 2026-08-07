"""Normalize raw DNS records into a :class:`DnsProfile`.

Kept pure so it can be unit-tested without touching the network: every
function here operates on the plain dict returned by :mod:`resolver`.
"""

from app.modules.dns.models import DnsProfile
from app.modules.dns.utils import has_dmarc, has_duplicates, has_spf

#: Record types stored in the resolver dict that count towards the profile.
COUNTABLE_TYPES = ["A", "AAAA", "MX", "TXT", "NS", "CNAME"]


def parse_dns_records(domain: str, records: dict) -> DnsProfile:
    """Convert the raw resolver payload into a normalized profile."""
    txt_records = _to_list(records.get("TXT"))
    ns_records = _to_list(records.get("NS"))
    mx_records = _to_list(records.get("MX"))
    caa_records = _to_list(records.get("caa"))

    return DnsProfile(
        domain=domain,
        ip_address=_to_list(records.get("A"))[0] if records.get("A") else None,
        ipv6_addresses=_to_list(records.get("AAAA")),
        resolves=bool(records.get("A") or records.get("AAAA")),
        mx_count=len(mx_records),
        ns_count=len(ns_records),
        txt_count=len(txt_records),
        caa_count=len(caa_records),
        cname_count=len(_to_list(records.get("CNAME"))),
        record_counts={qtype: len(_to_list(records.get(qtype))) for qtype in COUNTABLE_TYPES},
        mx_records=mx_records,
        ns_records=ns_records,
        txt_records=txt_records,
        caa_records=caa_records,
        dmarc_records=_to_list(records.get("dmarc_records")),
        spf=has_spf(txt_records),
        dmarc=has_dmarc(txt_records) or bool(records.get("dmarc_records")),
        dkim=bool(records.get("dkim")),
        dkim_selectors=_to_list(records.get("dkim_selectors")),
        spf_status="Valid" if has_spf(txt_records) else "Missing",
        dmarc_status="Valid" if has_dmarc(txt_records) or records.get("dmarc_records") else "Missing",
        dnssec=bool(records.get("dnssec")),
        nameserver_duplicates=has_duplicates(ns_records),
        ttl_min=_to_int(records.get("ttl_min")),
        resolution_consistent=_to_bool_or_none(records.get("resolution_consistent")),
    )


def _to_list(value) -> list[str]:
    if value is None:
        return []
    if isinstance(value, list):
        return [str(item).strip() for item in value if str(item).strip()]
    return [str(value).strip()]


def _to_int(value) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _to_bool_or_none(value) -> bool | None:
    if value is None:
        return None
    return bool(value)
