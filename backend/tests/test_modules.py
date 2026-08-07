from app.modules.dns.service import run_dns_check
from app.modules.headers.service import run_headers_check
from app.modules.whois.scanner import python_whois
from app.modules.whois.service import run_whois_check


def test_get_domain_info_returns_domain_details(monkeypatch):
    class DummyData:
        registrar = "Example Registrar"
        creation_date = "2020-01-01"
        expiration_date = "2030-01-01"
        name_servers = ["ns1.example.com"]

    monkeypatch.setattr(python_whois, "whois", lambda domain: DummyData())

    result = run_whois_check("example.com")

    assert result.module == "whois"
    assert result.details["domain"] == "example.com"
    assert result.details["registrar"] == "Example Registrar"
    assert result.details["name_servers"] == ["ns1.example.com"]


def test_get_dns_records_returns_ip(monkeypatch):
    import app.modules.dns.scanner as scanner

    fake_records = {
        "A": ["93.184.216.34"],
        "AAAA": [],
        "MX": [],
        "TXT": [],
        "NS": [],
        "CNAME": [],
        "spf_status": "Missing",
        "dmarc_status": "Missing",
    }
    monkeypatch.setattr(scanner, "resolve_domain", lambda domain: fake_records)

    result = run_dns_check("example.com")

    assert result.module == "dns"
    assert result.details["domain"] == "example.com"
    assert result.details["ip_address"] == "93.184.216.34"


def test_scan_headers_returns_security_summary(monkeypatch):
    class DummyResponse:
        def __init__(self):
            self.headers = {
                "Strict-Transport-Security": "max-age=31536000",
                "X-Frame-Options": "DENY",
            }
            self.url = "https://example.com"

    monkeypatch.setattr("app.modules.headers.scanner.requests.get", lambda url, timeout=10: DummyResponse())

    result = run_headers_check("example.com")

    assert result.module == "headers"
    assert result.details["url"] == "https://example.com"
    assert result.details["grade"] in {"A+", "A", "B", "C", "D", "F"}
    assert result.details["summary"]["present_headers"] >= 1
