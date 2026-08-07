from app.modules.url_analysis.service import run_url_analysis_check


def test_url_analysis_returns_expected_metrics():
    result = run_url_analysis_check("example.com")

    assert result.module == "url_analysis"
    assert result.details["domain"] == "example.com"
    assert result.details["uses_https"] is True
    assert result.details["is_valid"] is True
    assert result.details["is_ip_address"] is False
    assert result.score == 100
    assert isinstance(result.findings, list)
    assert all(
        f.recommendation and isinstance(f.recommendation, str) for f in result.findings
    )


def test_url_analysis_detects_ip_and_non_https_and_suspicious_path():
    result = run_url_analysis_check("http://93.184.216.34/login?next=1")

    assert result.details["is_ip_address"] is True
    assert result.details["uses_https"] is False
    descriptions = [f.description for f in result.findings]
    assert "The URL uses an IP address instead of a domain name." in descriptions
    assert "The website is not using HTTPS." in descriptions
    assert result.score < 100
    assert any(
        "HTTPS" in f.recommendation or "secure" in f.recommendation.lower()
        for f in result.findings
    )
