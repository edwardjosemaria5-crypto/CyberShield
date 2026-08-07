"""DNS record retrieval.

Responsible ONLY for collecting raw DNS records; all interpretation happens
in the parser and intelligence layers. Never raises: every failure degrades
to an empty/missing entry so downstream layers can report on it.
"""

import socket

try:
    import dns.resolver
    import dns.rdatatype

    HAS_DNSPYTHON = True
except ImportError:  # pragma: no cover - dnspython is a hard requirement
    HAS_DNSPYTHON = False

#: Well-known DKIM selector prefixes probed to detect signed mail.
DKIM_SELECTORS = ["default", "google", "k1", "s1", "selector1"]

#: Public resolvers used to cross-check A-record consistency.
PUBLIC_RESOLVERS = ["8.8.8.8", "1.1.1.1"]

QUERY_TYPES = ["A", "AAAA", "MX", "TXT", "NS", "CNAME"]
TIMEOUT_SECONDS = 3.0


def _hostname(domain: str) -> str:
    return domain.replace("https://", "").replace("http://", "").split("/")[0].split(":")[0].strip()


def _new_resolver() -> "dns.resolver.Resolver | None":
    if not HAS_DNSPYTHON:
        return None
    resolver = dns.resolver.Resolver()
    resolver.timeout = TIMEOUT_SECONDS
    resolver.lifetime = TIMEOUT_SECONDS
    return resolver


def resolve_domain(domain: str) -> dict:
    """Collect DNS records (A, AAAA, MX, TXT, NS, CNAME, CAA, DMARC, DKIM,
    DNSSEC, TTL) plus public-resolver consistency for a hostname."""
    hostname = _hostname(domain)
    records = {
        "A": [],
        "AAAA": [],
        "MX": [],
        "TXT": [],
        "NS": [],
        "CNAME": [],
        "spf_status": "Missing",
        "dmarc_status": "Missing",
        "dnssec": False,
        "caa": [],
        "dmarc_records": [],
        "dkim_selectors": [],
        "dkim": False,
        "ttl_min": None,
        "mx_entries": [],
        "resolution_consistent": None,
    }

    resolver = _new_resolver()
    if resolver is not None:
        _collect_basic_records(resolver, hostname, records)
        _collect_mx_details(resolver, hostname, records)
        _collect_caa(resolver, hostname, records)
        records["dnssec"] = _check_dnssec(resolver, hostname)
        _collect_dmarc(resolver, hostname, records)
        _collect_dkim(resolver, hostname, records)
        records["resolution_consistent"] = _check_consistency(hostname, records["A"])
    else:
        # Minimal fallback when dnspython is unavailable.
        try:
            records["A"].append(socket.gethostbyname(hostname))
        except Exception:  # noqa: BLE001
            pass

    _evaluate_email_policies(records)
    return records


def _collect_basic_records(resolver, hostname: str, records: dict) -> None:
    ttls: list[int] = []
    for qtype in QUERY_TYPES:
        try:
            answers = resolver.resolve(hostname, qtype)
            records[qtype] = [str(rdata).strip('"') for rdata in answers]
            if answers.rrset is not None:
                ttls.append(answers.rrset.ttl)
        except Exception:  # noqa: BLE001 - NXDOMAIN/NoAnswer are normal
            continue
    records["ttl_min"] = min(ttls) if ttls else None


def _collect_mx_details(resolver, hostname: str, records: dict) -> None:
    if not records["MX"]:
        return
    try:
        answers = resolver.resolve(hostname, "MX")
        records["mx_entries"] = [
            {
                "preference": rdata.preference,
                "exchange": str(rdata.exchange).rstrip(".").lower(),
            }
            for rdata in answers
        ]
    except Exception:  # noqa: BLE001
        pass


def _collect_caa(resolver, hostname: str, records: dict) -> None:
    try:
        answers = resolver.resolve(hostname, "CAA")
        records["caa"] = [str(rdata).strip('"') for rdata in answers]
    except Exception:  # noqa: BLE001
        pass


def _check_dnssec(resolver, hostname: str) -> bool:
    """DNSSEC is enabled when the zone publishes a DNSKEY record set."""
    try:
        resolver.resolve(hostname, "DNSKEY")
        return True
    except Exception:  # noqa: BLE001
        return False


def _collect_dmarc(resolver, hostname: str, records: dict) -> None:
    try:
        answers = resolver.resolve(f"_dmarc.{hostname}", "TXT")
        for rdata in answers:
            value = str(rdata).strip('"')
            if value.lstrip().lower().startswith("v=dmarc1"):
                records["dmarc_records"].append(value)
    except Exception:  # noqa: BLE001
        pass


def _collect_dkim(resolver, hostname: str, records: dict) -> None:
    for selector in DKIM_SELECTORS:
        try:
            answers = resolver.resolve(f"{selector}._domainkey.{hostname}", "TXT")
            if answers:
                records["dkim_selectors"].append(selector)
        except Exception:  # noqa: BLE001
            continue
    records["dkim"] = bool(records["dkim_selectors"])


def _check_consistency(hostname: str, ip_addresses: list[str]) -> bool | None:
    """Compare A records from the system resolver against public resolvers.

    Returns None when the comparison could not be performed (e.g. no A
    records or the public resolver is unreachable).
    """
    if not ip_addresses or not HAS_DNSPYTHON:
        return None
    try:
        resolver = dns.resolver.Resolver(configure=False)
        resolver.nameservers = PUBLIC_RESOLVERS
        resolver.timeout = TIMEOUT_SECONDS
        resolver.lifetime = TIMEOUT_SECONDS
        answers = resolver.resolve(hostname, "A")
        public_ips = {str(rdata) for rdata in answers}
        return public_ips == set(ip_addresses)
    except Exception:  # noqa: BLE001
        return None


def _evaluate_email_policies(records: dict) -> None:
    for txt in records["TXT"]:
        if "v=spf1" in txt:
            records["spf_status"] = "Valid"
        if "v=DMARC1" in txt:
            records["dmarc_status"] = "Valid"
    if records["dmarc_records"]:
        records["dmarc_status"] = "Valid"
