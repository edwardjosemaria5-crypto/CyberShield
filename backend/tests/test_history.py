"""Tests for the persistent scan history (service + API)."""

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import delete

from app.database.connection import SessionLocal
from app.database.models import Scan
from app.main import app
from app.schemas.analysis_response import AnalysisResponse
from app.services import history_service


def make_analysis(
    scan_id: str = "CS-2026-TEST0001",
    target: str = "example.com",
    trust_score: int = 81,
) -> AnalysisResponse:
    return AnalysisResponse(
        scan_id=scan_id,
        target=target,
        normalized_url=f"https://{target}",
        domain=target,
        started_at="2026-08-07T10:00:00Z",
        completed_at="2026-08-07T10:05:00Z",
        trust_score=trust_score,
        confidence=89,
        verdict="Low Risk",
        summary={"critical": 0, "high": 0, "medium": 1, "low": 2, "info": 3},
        modules=[],
        findings=[
            {
                "title": "Missing HSTS header",
                "severity": "medium",
                "description": "No Strict-Transport-Security header found.",
                "recommendation": "Add the HSTS header.",
            }
        ],
    )


@pytest.fixture(autouse=True)
def clean_history():
    yield
    with SessionLocal() as session:
        session.execute(delete(Scan))
        session.commit()


def test_save_then_get_round_trip():
    analysis = make_analysis()
    saved_id = history_service.save_scan(analysis)

    assert saved_id == analysis.scan_id
    loaded = history_service.get_scan(analysis.scan_id)
    assert loaded is not None
    assert loaded.scan_id == analysis.scan_id
    assert loaded.target == "example.com"
    assert loaded.trust_score == 81
    assert loaded.verdict == "Low Risk"
    assert loaded.summary.medium == 1
    assert loaded.summary.info == 3
    assert len(loaded.findings) == 1
    assert loaded.findings[0].title == "Missing HSTS header"


def test_get_scan_by_id_via_api():
    analysis = make_analysis(scan_id="CS-2026-API0001")
    history_service.save_scan(analysis)

    client = TestClient(app)
    response = client.get("/history/CS-2026-API0001")

    assert response.status_code == 200
    body = response.json()
    assert body["scan_id"] == "CS-2026-API0001"
    assert body["target"] == "example.com"
    assert body["trust_score"] == 81
    assert body["confidence"] == 89
    assert body["verdict"] == "Low Risk"
    assert body["summary"]["medium"] == 1
    assert body["findings"][0]["title"] == "Missing HSTS header"
    assert body["modules"] == []


def test_missing_scan_returns_404():
    client = TestClient(app)
    response = client.get("/history/CS-2026-DOESNT")

    assert response.status_code == 404
    assert response.json()["detail"] == "Scan not found."


def test_invalid_scan_ids_return_404():
    client = TestClient(app)
    for bad_id in ("../etc/passwd", "CS-2026-zzzz", "not-a-scan-id", "CS-2026-1234"):
        response = client.get(f"/history/{bad_id}")
        assert response.status_code == 404, bad_id


def test_list_scans_pagination():
    for index in range(5):
        history_service.save_scan(make_analysis(scan_id=f"CS-2026-PAGE{index:04d}", target=f"t{index}.com"))

    client = TestClient(app)

    page1 = client.get("/history?limit=2&offset=0").json()
    assert page1["total"] == 5
    assert page1["limit"] == 2
    assert page1["offset"] == 0
    assert [item["scan_id"] for item in page1["items"]] == ["CS-2026-PAGE0004", "CS-2026-PAGE0003"]

    page2 = client.get("/history?limit=2&offset=2").json()
    assert [item["scan_id"] for item in page2["items"]] == ["CS-2026-PAGE0002", "CS-2026-PAGE0001"]

    beyond = client.get("/history?limit=2&offset=10").json()
    assert beyond["items"] == []
    assert beyond["total"] == 5


def test_list_scans_validation_errors():
    client = TestClient(app)
    assert client.get("/history?limit=0").status_code == 422
    assert client.get("/history?limit=101").status_code == 422
    assert client.get("/history?offset=-1").status_code == 422


def test_persistence_survives_client_recreation():
    """Rows live in the SQLite file, so a brand new app/test client sees them."""
    client1 = TestClient(app)
    client1.get("/history/CS-2026-TEST0001")

    history_service.save_scan(make_analysis())
    client2 = TestClient(app)
    response = client2.get("/history/CS-2026-TEST0001")
    assert response.status_code == 200
    assert response.json()["scan_id"] == "CS-2026-TEST0001"


def test_scan_endpoint_persists_result(monkeypatch):
    captured = {}

    def fake_run(domain: str) -> AnalysisResponse:
        analysis = make_analysis(scan_id="CS-2026-SCAN0001", target=domain)
        captured["analysis"] = analysis
        return analysis

    monkeypatch.setattr("app.services.scan_manager.ScanManager.run", lambda self, target: fake_run(target))
    client = TestClient(app)

    response = client.get("/scan/example.com")

    assert response.status_code == 200
    body = response.json()
    assert body["scan_id"] == "CS-2026-SCAN0001"
    assert body["target"] == "example.com"
    assert body["trust_score"] == 81

    stored = history_service.get_scan("CS-2026-SCAN0001")
    assert stored is not None
    assert stored.scan_id == body["scan_id"]
    assert stored.trust_score == body["trust_score"]
    assert stored.verdict.value == body["verdict"]


def test_persistence_failure_does_not_break_scan(monkeypatch):
    def boom(*args, **kwargs):
        raise RuntimeError("disk is full")

    monkeypatch.setattr("app.services.scan_service.save_scan", boom)
    monkeypatch.setattr(
        "app.services.scan_manager.ScanManager.run",
        lambda self, target: make_analysis(scan_id="CS-2026-FAIL0001", target=target),
    )
    client = TestClient(app)

    response = client.get("/scan/example.com")

    assert response.status_code == 200
    assert response.json()["scan_id"] == "CS-2026-FAIL0001"