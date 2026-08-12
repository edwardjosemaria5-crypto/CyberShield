from fastapi.testclient import TestClient

from app.api.routes import health
from app.core.config import (
    AI_ENABLED,
    GOOGLE_SAFE_BROWSING_API_KEY,
    THREAT_PROVIDER_ENABLED,
    VIRUS_TOTAL_API_KEY,
)
from app.main import app


def test_health_route_returns_status_payload():
    client = TestClient(app)

    response = client.get("/health")

    assert response.status_code == 200
    assert response.json()["status"] == "Healthy"


def test_health_preserves_existing_fields():
    client = TestClient(app)

    payload = client.get("/health").json()

    assert payload["application"] == "CyberShield"
    assert payload["version"] == "2.0.0"


def test_health_exposes_threat_intel_status_fields():
    client = TestClient(app)

    payload = client.get("/health").json()

    threat_intel = payload["threat_intel"]
    assert threat_intel["enabled"] is THREAT_PROVIDER_ENABLED
    assert threat_intel["google_safe_browsing_configured"] is bool(GOOGLE_SAFE_BROWSING_API_KEY)
    assert threat_intel["virustotal_configured"] is bool(VIRUS_TOTAL_API_KEY)


def test_health_exposes_ai_enabled_field():
    client = TestClient(app)

    payload = client.get("/health").json()

    assert payload["ai"]["enabled"] is AI_ENABLED


def test_health_response_contains_no_secret_values():
    client = TestClient(app)

    payload = client.get("/health").json()

    serialized = str(payload)
    if GOOGLE_SAFE_BROWSING_API_KEY:
        assert GOOGLE_SAFE_BROWSING_API_KEY not in serialized
    if VIRUS_TOTAL_API_KEY:
        assert VIRUS_TOTAL_API_KEY not in serialized
    assert "api_key" not in serialized.lower()


def test_health_missing_provider_keys_report_unconfigured(monkeypatch):
    monkeypatch.setattr(health, "GOOGLE_SAFE_BROWSING_API_KEY", "")
    monkeypatch.setattr(health, "VIRUS_TOTAL_API_KEY", "")
    client = TestClient(app)

    threat_intel = client.get("/health").json()["threat_intel"]

    assert threat_intel["google_safe_browsing_configured"] is False
    assert threat_intel["virustotal_configured"] is False