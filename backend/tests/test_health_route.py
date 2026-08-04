from fastapi.testclient import TestClient

from app.api.routes import health
from app.main import app


def test_health_route_returns_status_payload():
    client = TestClient(app)

    response = client.get("/health")

    assert response.status_code == 200
    assert response.json()["status"] == "Healthy"
