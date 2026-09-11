"""P7-02: legacy module routes bound user-controlled target/domain paths.

The shared scan-target maximum (2048 characters, matching the primary /scan
contract) is enforced on every legacy module route that accepts a
user-controlled domain/target path parameter. Valid bounded input is accepted
per the existing route contract; oversized and malformed input is rejected
before any scanner runs.
"""

import pytest
from fastapi.testclient import TestClient

from app.core.constants import MAX_TARGET_LENGTH
from app.main import app
from app.schemas.module_result import ModuleResult

DOMAIN_ROUTES = [
    ("/whois/", "app.modules.whois.service.run_whois_check", "whois"),
    ("/dns/", "app.modules.dns.service.run_dns_check", "dns"),
    ("/ssl/", "app.modules.ssl.service.run_ssl_check", "ssl"),
    ("/headers/", "app.modules.headers.service.run_headers_check", "headers"),
    ("/reputation/", "app.modules.reputation.service.run_reputation_check", "reputation"),
    (
        "/typosquatting/",
        "app.modules.typosquatting.service.run_typosquatting_check",
        "typosquatting",
    ),
    (
        "/brand-detection/",
        "app.modules.brand_detection.service.run_brand_detection_check",
        "brand_detection",
    ),
    (
        "/threatintel/",
        "app.modules.threatintel.service.run_threatintel_check",
        "threatintel",
    ),
]

# The url-analysis route calls service.scan() on a module-level instance; the
# class method is patched so every instance resolves the fake.
URL_ANALYSIS_ROUTE = (
    "/url-analysis/",
    "app.modules.url_analysis.service.URLAnalysisService.scan",
    "url_analysis",
)
PORT_ROUTE = ("/ports/", "app.modules.ports.service.run_ports_check", "ports")


def _ok_result(module):
    return ModuleResult(module=module, status="ok", score=100, confidence=100)


def _unreachable(*_args, **_kwargs):
    raise AssertionError("scanner must not run for oversized input")


@pytest.mark.parametrize("prefix,svc_path,module_name", DOMAIN_ROUTES)
def test_domain_route_accepts_bounded_target(monkeypatch, prefix, svc_path, module_name):
    monkeypatch.setattr(svc_path, lambda domain: _ok_result(module_name))
    client = TestClient(app)

    response = client.get(f"{prefix}example.com")

    assert response.status_code == 200
    assert response.json()["module"] == module_name


@pytest.mark.parametrize("prefix,svc_path,module_name", DOMAIN_ROUTES)
def test_domain_route_rejects_oversized_target(monkeypatch, prefix, svc_path, module_name):
    monkeypatch.setattr(svc_path, _unreachable)
    client = TestClient(app)

    response = client.get(f"{prefix}{'a' * (MAX_TARGET_LENGTH + 1)}")

    assert response.status_code == 422
    detail = response.json()["detail"]
    assert isinstance(detail, list) and detail
    assert any("2048" in (item.get("msg") or "") for item in detail)


@pytest.mark.parametrize("prefix,svc_path,module_name", DOMAIN_ROUTES)
def test_domain_route_rejects_malformed_target(monkeypatch, prefix, svc_path, module_name):
    client = TestClient(app)

    response = client.get(f"{prefix}example.com/path")

    assert response.status_code == 404


def test_url_analysis_route_accepts_bounded_target(monkeypatch):
    monkeypatch.setattr(URL_ANALYSIS_ROUTE[1], lambda self, url: _ok_result("url_analysis"))
    client = TestClient(app)

    response = client.get(f"{URL_ANALYSIS_ROUTE[0]}https://example.com/path")

    assert response.status_code == 200
    assert response.json()["module"] == "url_analysis"


def test_url_analysis_route_rejects_oversized_target(monkeypatch):
    monkeypatch.setattr(URL_ANALYSIS_ROUTE[1], _unreachable)
    client = TestClient(app)

    response = client.get(f"{URL_ANALYSIS_ROUTE[0]}{'a' * (MAX_TARGET_LENGTH + 1)}")

    assert response.status_code == 422
    detail = response.json()["detail"]
    assert isinstance(detail, list) and detail
    assert any("2048" in (item.get("msg") or "") for item in detail)


def test_ports_route_accepts_bounded_target(monkeypatch):
    monkeypatch.setattr(PORT_ROUTE[1], lambda host: _ok_result("ports"))
    client = TestClient(app)

    response = client.get(f"{PORT_ROUTE[0]}example.com")

    assert response.status_code == 200
    assert response.json()["module"] == "ports"


def test_ports_route_rejects_oversized_target(monkeypatch):
    monkeypatch.setattr(PORT_ROUTE[1], _unreachable)
    client = TestClient(app)

    response = client.get(f"{PORT_ROUTE[0]}{'a' * (MAX_TARGET_LENGTH + 1)}")

    assert response.status_code == 422
    detail = response.json()["detail"]
    assert isinstance(detail, list) and detail
    assert any("2048" in (item.get("msg") or "") for item in detail)


def test_primary_scan_contract_matches_shared_constant():
    from app.api.routes.scan import MAX_TARGET_LENGTH as PRIMARY_MAX

    assert PRIMARY_MAX == MAX_TARGET_LENGTH == 2048