from app.modules.url_analysis.service import run_url_analysis_check


def test_url_analysis_returns_expected_metrics():
    result = run_url_analysis_check("example.com")

    assert result["domain"] == "example.com"
    assert result["uses_https"] is True
    assert result["is_valid"] is True
    assert result["is_ip_address"] is False
    assert result["risk_score"] == 100
    assert isinstance(result["findings"], list)
    assert isinstance(result["recommendations"], list)


def test_url_analysis_detects_ip_and_non_https_and_suspicious_path():
    result = run_url_analysis_check("http://93.184.216.34/login?next=1")

    assert result["is_ip_address"] is True
    assert result["uses_https"] is False
    assert "The URL uses an IP address instead of a domain name." in result["findings"]
    assert "The website is not using HTTPS." in result["findings"]
    assert result["risk_score"] < 100
    assert any("HTTPS" in rec or "secure" in rec.lower() for rec in result["recommendations"])
