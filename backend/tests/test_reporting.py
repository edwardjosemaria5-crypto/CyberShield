"""Tests for the report export pipeline (JSON / CSV / PDF)."""

import io
import json

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.modules.reporting import csv as csv_exporter
from app.modules.reporting import json as json_exporter
from app.modules.reporting import pdf as pdf_exporter
from app.schemas.analysis_response import AnalysisResponse
from app.services import history_service, reporting_service


def make_analysis(
    scan_id: str = "CS-2026-REP0001",
    target: str = "example.com",
    modules_count: int = 3,
    findings_count: int = 2,
    description: str = "No Strict-Transport-Security header found.",
    recommendation: str = "Add the HSTS header with a long max-age value.",
) -> AnalysisResponse:
    findings = [
        {
            "title": f"Finding {i}",
            "severity": "medium" if i % 2 == 0 else "low",
            "description": description,
            "recommendation": recommendation,
            "evidence": "evidence-" + ("x" * 200),
        }
        for i in range(findings_count)
    ]
    modules = [
        {
            "module": f"module_{i}",
            "status": "ok",
            "score": 90 - i,
            "confidence": 95,
            "findings": [],
            "details": {"detail_key": f"value-{i}"},
        }
        for i in range(modules_count)
    ]
    return AnalysisResponse(
        scan_id=scan_id,
        target=target,
        normalized_url=f"https://{target}",
        domain=target,
        started_at="2026-08-07T10:00:00Z",
        completed_at="2026-08-07T10:05:00Z",
        trust_score=81,
        confidence=89,
        verdict="Low Risk",
        summary={"critical": 0, "high": 0, "medium": 1, "low": 2, "info": 3},
        modules=modules,
        findings=findings,
    )


# ---------------------------------------------------------------------------
# Unit tests: exporters
# ---------------------------------------------------------------------------


def test_json_export_is_valid_and_complete():
    text = json_exporter.generate_json_report(make_analysis())
    data = json.loads(text)
    assert data["scan_id"] == "CS-2026-REP0001"
    assert data["target"] == "example.com"
    assert data["trust_score"] == 81
    assert data["verdict"] == "Low Risk"
    assert len(data["modules"]) == 3
    assert len(data["findings"]) == 2


def test_json_export_accepts_analysis_response_object():
    analysis = make_analysis()
    text = json_exporter.generate_json_report(analysis)
    data = json.loads(text)
    assert data["scan_id"] == analysis.scan_id
    assert data["trust_score"] == analysis.trust_score


def test_csv_export_is_valid_and_complete():
    text = csv_exporter.generate_csv_report(make_analysis())
    reader = list(__import__("csv").reader(io.StringIO(text)))
    assert reader[0] == ["Category", "Key", "Value"]
    joined = " ".join(" ".join(row) for row in reader)
    assert "example.com" in joined
    assert "81" in joined
    assert "Low Risk" in joined
    assert "Finding 0" in joined
    assert "module_0" in joined


def test_csv_export_guards_formula_injection():
    text = csv_exporter.generate_csv_report(make_analysis(target="=SUM(A1:A9)"))
    rows = {row[1]: row[2] for row in __import__("csv").reader(io.StringIO(text))}
    assert rows["Target URL"] == "'=SUM(A1:A9)"  # formula cell neutralized
    assert rows["Domain"] == "'=SUM(A1:A9)"


def _analysis_with_ai_and_threat_intel() -> AnalysisResponse:
    """An analysis carrying the optional AI explanation and a threatintel
    module with a normalized correlation block."""
    payload = make_analysis(modules_count=1).model_dump()
    payload["modules"] = [
        {
            "module": "threatintel",
            "status": "ok",
            "score": 61,
            "confidence": 90,
            "findings": [],
            "details": {
                "threat_intel_correlation": {
                    "available_count": 2,
                    "malicious_count": 1,
                    "suspicious_count": 0,
                    "clean_count": 1,
                    "unavailable_count": 0,
                    "agreement": "partial",
                    "consensus": "conflicted",
                    "conflict": True,
                    "malicious_confidence": 60,
                    "suspicious_confidence": 0,
                    "signals": [
                        {
                            "provider": "google",
                            "status": "available",
                            "malicious": True,
                            "categories": ["MALWARE"],
                        }
                    ],
                }
            },
        }
    ]
    payload["ai_explanation"] = {
        "summary": "Moderate risk indicated by headers findings.",
        "why_risky": "Missing security headers lower the posture.",
        "key_risk_factors": ["Missing HSTS"],
        "technical_explanation": "HTTP stack lacks hardening headers.",
        "recommended_actions": ["Enable HSTS"],
    }
    return AnalysisResponse.model_validate(payload)


def test_csv_export_includes_ai_explanation():
    from csv import reader

    text = csv_exporter.generate_csv_report(_analysis_with_ai_and_threat_intel())
    rows = list(reader(io.StringIO(text)))
    ai_rows = [row for row in rows if row[0] == "AI Explanation"]
    by_key = {row[1]: row[2] for row in ai_rows}
    assert by_key["Summary"] == "Moderate risk indicated by headers findings."
    assert by_key["Why risky"] == "Missing security headers lower the posture."
    factors = [row[2] for row in ai_rows if row[1] == "Key risk factor"]
    actions = [row[2] for row in ai_rows if row[1] == "Recommended action"]
    assert factors == ["Missing HSTS"]
    assert actions == ["Enable HSTS"]


def test_csv_export_includes_threat_intel():
    from csv import reader

    text = csv_exporter.generate_csv_report(_analysis_with_ai_and_threat_intel())
    rows = list(reader(io.StringIO(text)))
    ti_rows = [row for row in rows if row[0] == "Threat Intel"]
    by_key = {row[1]: row[2] for row in ti_rows}
    assert by_key["Available count"] == "2"
    assert by_key["Malicious count"] == "1"
    assert by_key["Agreement"] == "partial"
    assert by_key["Consensus"] == "conflicted"
    assert by_key["Conflict"] == "True"
    signal_rows = [(row[1], row[2]) for row in rows if row[0] == "Threat Intel Signal"]
    assert any(provider == "google" and "MALWARE" in value for provider, value in signal_rows)


def test_csv_export_omits_ai_when_absent():
    text = csv_exporter.generate_csv_report(make_analysis())
    rows = list(__import__("csv").reader(io.StringIO(text)))
    assert all(row[0] != "AI Explanation" for row in rows)


def test_pdf_export_includes_ai_and_threat_intel(monkeypatch):
    captured: list[str] = []
    original_paragraph = pdf_exporter.Paragraph

    def spy(*args, **kwargs):
        captured.append(str(args[0]))
        return original_paragraph(*args, **kwargs)

    monkeypatch.setattr(pdf_exporter, "Paragraph", spy)
    content = pdf_exporter.generate_pdf_report(
        _analysis_with_ai_and_threat_intel().model_dump(mode="json")
    )
    assert content[:5] == b"%PDF-"
    joined = "\n".join(captured)
    assert "Threat Intelligence" in joined
    assert "Provider Conflict" in joined
    assert "AI Security Explanation" in joined
    assert "Moderate risk indicated" in joined
    assert "Missing HSTS" in joined


def test_pdf_export_draws_without_ai_or_threat_intel_data():
    content = pdf_exporter.generate_pdf_report(make_analysis().model_dump(mode="json"))
    assert content[:5] == b"%PDF-"
    assert len(content) > 500


def test_pdf_export_is_structurally_valid():
    content = pdf_exporter.generate_pdf_report(make_analysis().model_dump(mode="json"))
    assert content[:5] == b"%PDF-"
    assert len(content) > 500
    assert b"%%EOF" in content[-512:]


def test_pdf_export_handles_long_and_unicode_content():
    analysis = make_analysis(
        description="À test — “quoted” with 'apostrophes' and ™ symbols " + "x" * 2000,
        recommendation="Fix: " + "y" * 1500,
        target="https://example.com/" + "segment/" * 30,
    )
    content = pdf_exporter.generate_pdf_report(analysis.model_dump(mode="json"))
    assert content[:5] == b"%PDF-"
    assert len(content) > 1000


def test_pdf_export_escapes_user_markup():
    analysis = make_analysis(
        target="example.com",
        description="<script>alert(1)</script> & <b>bold injection</b> & unclosed <tag",
    )
    content = pdf_exporter.generate_pdf_report(analysis.model_dump(mode="json"))
    assert content[:5] == b"%PDF-"
    assert b"%%EOF" in content[-512:]


def test_pdf_export_without_unicode_font(monkeypatch):
    analysis = make_analysis()
    monkeypatch.setattr(pdf_exporter, "_HAS_UNICODE_FONT", False)
    content = pdf_exporter.generate_pdf_report(analysis.model_dump(mode="json"))
    assert content[:5] == b"%PDF-"
    assert len(content) > 500


def test_pdf_export_without_reportlab_raises(monkeypatch):
    monkeypatch.setattr(pdf_exporter, "REPORTLAB_AVAILABLE", False)
    with pytest.raises(RuntimeError, match="reportlab"):
        pdf_exporter.generate_pdf_report(make_analysis().model_dump(mode="json"))


def test_table_widths_fit_page():
    for ratios in ([0.28, 0.72], [0.36, 0.14, 0.16, 0.18, 0.16], [0.5, 0.5]):
        widths = pdf_exporter._table_widths(ratios)
        assert sum(widths) == pytest.approx(pdf_exporter.AVAILABLE_PAGE_WIDTH)
        assert all(w > 0 for w in widths)


def test_page_width_is_sane():
    assert pdf_exporter.AVAILABLE_PAGE_WIDTH < pdf_exporter.PAGE_WIDTH
    assert pdf_exporter.AVAILABLE_PAGE_WIDTH > 300


# ---------------------------------------------------------------------------
# Service tests
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("fmt,ext,expected", [("json", "json", b"{"), ("csv", "csv", b"Category"), ("pdf", "pdf", b"%PDF-")])
def test_reporting_service_produces_all_formats(fmt, ext, expected):
    report = reporting_service.generate_report(make_analysis(), fmt)
    assert report.format == fmt
    assert report.filename == f"cybershield-CS-2026-REP0001.{ext}"
    assert report.content.startswith(expected)
    assert report.media_type.startswith({"json": "application", "csv": "text", "pdf": "application"}[fmt])


def test_reporting_service_rejects_unknown_format():
    with pytest.raises(reporting_service.UnsupportedFormatError):
        reporting_service.generate_report(make_analysis(), "xml")


def test_reporting_service_filename_never_uses_target():
    report = reporting_service.generate_report(make_analysis(target="../../etc/passwd"), "json")
    assert "passwd" not in report.filename
    assert report.filename == "cybershield-CS-2026-REP0001.json"


# ---------------------------------------------------------------------------
# API tests
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def seed_and_clean():
    analysis = make_analysis()
    history_service.save_scan(analysis)
    yield
    from sqlalchemy import delete
    from app.database.connection import SessionLocal
    from app.database.models import Scan

    with SessionLocal() as session:
        session.execute(delete(Scan))
        session.commit()


def test_api_export_json_from_history():
    client = TestClient(app)
    response = client.get("/reports/CS-2026-REP0001/json")
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("application/json")
    assert response.headers["content-disposition"].startswith('attachment; filename="cybershield-CS-2026-REP0001.json"')
    data = response.json()
    assert data["target"] == "example.com"
    assert data["trust_score"] == 81
    assert data["verdict"] == "Low Risk"


def test_api_export_csv_from_history():
    response = TestClient(app).get("/reports/CS-2026-REP0001/csv")
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/csv")
    assert "example.com" in response.text
    assert "Category,Key,Value" in response.text


def test_api_export_pdf_from_history():
    response = TestClient(app).get("/reports/CS-2026-REP0001/pdf")
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("application/pdf")
    assert response.content[:5] == b"%PDF-"


def test_api_export_missing_scan_returns_404():
    response = TestClient(app).get("/reports/CS-2026-NOPE123/json")
    assert response.status_code == 404


def test_api_export_malformed_scan_id_returns_404():
    client = TestClient(app)
    for bad in ("../etc/passwd", "..%2Fetc%2Fpasswd", "not a scan!", "a" * 100):
        assert client.get(f"/reports/{bad}/json").status_code == 404


def test_api_export_unsupported_format_returns_422():
    response = TestClient(app).get("/reports/CS-2026-REP0001/xml")
    assert response.status_code == 422


def test_api_export_headers_are_safe():
    response = TestClient(app).get("/reports/CS-2026-REP0001/pdf")
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["cache-control"] == "no-store"
