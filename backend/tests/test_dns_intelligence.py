"""Tests for the DNS Intelligence Engine.

Intelligence units operate on :class:`DnsProfile` directly; service-level
tests inject a stub resolver returning the same plain-dict contract as
:func:`app.modules.dns.resolver.resolve_domain`, so no network access is
ever required.
"""

from app.modules.dns.intelligence import evaluate_profile
from app.modules.dns.models import DnsProfile
from app.modules.dns.parser import parse_dns_records
from app.modules.dns.service import scan_dns_module

CAA_OK = ["0 issue 'letsencrypt.org'"]


def _profile(**overrides) -> DnsProfile:
    defaults = {
        "domain": "example.com",
        "ip_address": "93.184.216.34",
        "ipv6_addresses": [],
        "resolves": True,
        "mx_count": 2,
        "ns_count": 2,
        "txt_count": 1,
        "caa_count": 1,
        "mx_records": ["10 mail.example.com."],
        "ns_records": ["ns1.example.com", "ns2.example.com"],
        "txt_records": ["v=spf1 -all"],
        "caa_records": CAA_OK,
        "spf": True,
        "dmarc": True,
        "dkim": True,
        "dnssec": True,
        "ttl_min": 300,
        "resolution_consistent": True,
    }
    defaults.update(overrides)
    return DnsProfile(**defaults)


def _titles(result):
    return [f.title for f in result.findings]


# ------------------------------------------------------------ intelligence units

def test_healthy_profile_scores_100():
    result = evaluate_profile(_profile())

    assert result.score == 100
    assert result.findings == []
    assert result.confidence == 90


def test_missing_spf_flagged_medium():
    result = evaluate_profile(_profile(spf=False, txt_records=[]))

    assert "SPF Record Missing" in _titles(result)
    assert result.score == 85
    finding = next(f for f in result.findings if f.title == "SPF Record Missing")
    assert finding.severity == "medium"
    assert finding.explanation and finding.recommendation
    assert finding.confidence == 90


def test_missing_dmarc_flagged_medium():
    result = evaluate_profile(_profile(dmarc=False))

    assert "DMARC Policy Missing" in _titles(result)
    assert result.score == 85


def test_missing_mx_flagged_low():
    result = evaluate_profile(_profile(mx_count=0, mx_records=[]))

    assert "No MX Records" in _titles(result)
    assert result.score == 95


def test_missing_spf_and_dmarc_stack():
    result = evaluate_profile(_profile(spf=False, dmarc=False))

    assert result.score == 70
    assert len(result.findings) == 2


def test_dnssec_disabled_flagged():
    result = evaluate_profile(_profile(dnssec=False))

    assert "DNSSEC Disabled" in _titles(result)
    assert result.score == 95


def test_missing_caa_is_informational_only():
    result = evaluate_profile(_profile(caa_count=0, caa_records=[]))

    assert "CAA Record Missing" in _titles(result)
    assert result.findings[0].severity == "info"
    assert result.score == 100


def test_suspicious_caa_flagged():
    result = evaluate_profile(_profile(caa_records=["0 iodef 'mailto:abuse@example.com'"]))

    assert "Suspicious CAA Configuration" in _titles(result)
    assert result.score == 90


def test_excessive_nameservers_flagged():
    ns = [f"ns{i}.example.com" for i in range(6)]
    result = evaluate_profile(_profile(ns_count=6, ns_records=ns))

    assert "Excessive Name Servers" in _titles(result)
    assert result.score == 90


def test_single_nameserver_flagged_low():
    result = evaluate_profile(_profile(ns_count=1, ns_records=["ns1.example.com"]))

    assert "Single Name Server" in _titles(result)
    assert result.score == 95


def test_duplicate_nameservers_flagged():
    result = evaluate_profile(
        _profile(ns_count=2, ns_records=["ns1.example.com", "ns1.example.com"], nameserver_duplicates=True)
    )

    assert "Duplicate Name Servers" in _titles(result)
    assert result.score == 90


def test_low_ttl_flagged_info():
    result = evaluate_profile(_profile(ttl_min=30))

    assert "Very Low TTL Values" in _titles(result)
    assert result.score == 98


def test_inconsistent_resolution_flagged():
    result = evaluate_profile(_profile(resolution_consistent=False))

    assert "Inconsistent DNS Resolution" in _titles(result)
    assert result.score == 85


def test_domain_not_resolving_is_high():
    result = evaluate_profile(
        _profile(ip_address=None, ipv6_addresses=[], resolves=False, caa_count=0, caa_records=[])
    )

    assert "Domain Does Not Resolve" in _titles(result)
    assert result.findings[0].severity == "high"
    assert result.score == 40


# ------------------------------------------------------------ parser units

def test_parser_normalizes_missing_keys():
    records = {
        "A": ["93.184.216.34"],
        "MX": [],
        "TXT": [],
        "spf_status": "Missing",
        "dmarc_status": "Missing",
    }

    profile = parse_dns_records("example.com", records)

    assert profile.domain == "example.com"
    assert profile.ip_address == "93.184.216.34"
    assert profile.resolves is True
    assert profile.spf is False
    assert profile.dmarc is False
    assert profile.dnssec is False
    assert profile.ttl_min is None


def test_parser_detects_email_policies():
    records = {
        "A": ["93.184.216.34"],
        "TXT": ["v=spf1 include:_spf.example.com ~all", "v=DMARC1; p=reject"],
        "dmarc_records": [],
        "MX": ["10 mail.example.com."],
        "NS": ["ns1.example.com"],
        "CNAME": [],
    }

    profile = parse_dns_records("example.com", records)

    assert profile.spf is True
    assert profile.dmarc is True
    assert profile.mx_count == 1
    assert profile.record_counts["TXT"] == 2


# ------------------------------------------------------------ service level

def _records(**overrides) -> dict:
    defaults = {
        "A": ["93.184.216.34"],
        "AAAA": [],
        "MX": ["10 mail.example.com."],
        "TXT": ["v=spf1 -all"],
        "NS": ["ns1.example.com", "ns2.example.com"],
        "CNAME": [],
        "spf_status": "Valid",
        "dmarc_status": "Valid",
        "dnssec": True,
        "caa": CAA_OK,
        "dmarc_records": ["v=DMARC1; p=reject"],
        "dkim_selectors": ["default"],
        "dkim": True,
        "ttl_min": 300,
        "mx_entries": [{"preference": 10, "exchange": "mail.example.com"}],
        "resolution_consistent": True,
    }
    defaults.update(overrides)
    return defaults


def test_healthy_domain_end_to_end():
    result = scan_dns_module("example.com", resolver=lambda _d: _records())

    assert result.module == "dns"
    assert result.status == "ok"
    assert result.score == 100
    assert result.confidence == 90
    assert result.findings == []
    details = result.details
    assert details["domain"] == "example.com"
    assert details["ip_address"] == "93.184.216.34"
    assert details["spf"] is True
    assert details["dmarc"] is True
    assert details["dnssec"] is True
    assert details["record_counts"]["A"] == 1


def test_missing_spf_end_to_end():
    result = scan_dns_module("example.com", resolver=lambda _d: _records(TXT=[], spf_status="Missing"))

    assert "SPF Record Missing" in _titles(result)
    assert result.status == "warning"
    assert result.details["spf_status"] == "Missing"


def test_unresolvable_domain_end_to_end():
    result = scan_dns_module("nowhere.invalid", resolver=lambda _d: _records(A=[], AAAA=[]))

    assert "Domain Does Not Resolve" in _titles(result)
    assert result.status == "critical"
    assert result.score == 40
    assert result.details["ip_address"] is None


def test_https_prefix_is_normalized():
    result = scan_dns_module("https://example.com", resolver=lambda _d: _records())

    assert result.details["domain"] == "example.com"
