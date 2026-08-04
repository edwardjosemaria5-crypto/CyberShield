from fastapi.testclient import TestClient

from app.main import app


def test_scan_endpoint_returns_summary(monkeypatch):
    def fake_run_scan(domain: str):
        return {
            "target": domain,
            "security_score": 82,
            "overall_risk": "Medium",
            "modules": {
                "headers": {"status": "ok"},
                "dns": {"status": "ok"},
                "whois": {"status": "ok"},
            },
        }

    monkeypatch.setattr("app.api.routes.scan.run_scan", fake_run_scan)
    client = TestClient(app)

    response = client.get("/scan/example.com")

    assert response.status_code == 200
    assert response.json()["target"] == "example.com"
    assert response.json()["security_score"] == 82
