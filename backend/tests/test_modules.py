from app.modules.dns.service import run_dns_check
from app.modules.headers.service import run_headers_check
from app.modules.whois.service import run_whois_check


def test_get_domain_info_returns_domain_details(monkeypatch):
    class DummyData:
        registrar = "Example Registrar"
        creation_date = "2020-01-01"
        expiration_date = "2030-01-01"
        name_servers = ["ns1.example.com"]

    monkeypatch.setattr("app.modules.whois.scanner.whois.whois", lambda domain: DummyData())

    result = run_whois_check("example.com")

    assert result["domain"] == "example.com"
    assert result["registrar"] == "Example Registrar"
    assert result["name_servers"] == ["ns1.example.com"]


def test_get_dns_records_returns_ip(monkeypatch):
    monkeypatch.setattr("app.modules.dns.scanner.socket.gethostbyname", lambda domain: "93.184.216.34")

    result = run_dns_check("example.com")

    assert result["domain"] == "example.com"
    assert result["ip_address"] == "93.184.216.34"


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

    assert result["url"] == "https://example.com"
    assert result["overall_risk"] in {"Low", "Medium", "High"}
    assert result["summary"]["present_headers"] >= 1
