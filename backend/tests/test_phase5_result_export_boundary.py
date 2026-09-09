"""Phase 5 checkpoint: secure scan-result / export API boundary.

These HTTP-boundary tests lock the guarantees the result/export endpoints
must uphold: the endpoint is a thin presentation layer over the pipeline and
must never parse, resolve, re-score, or emit credential material itself.

The phase made NO production code changes: the secure result/export boundary
already exists (backend/app/api/routes/{scan,history,reports}.py, built on the
shared scan pipeline in backend/app/services/scan_manager.py). This file pins
those guarantees so a regression cannot reintroduce them silently.
"""

import socket

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import delete

from app.database.connection import SessionLocal
from app.database.models import Scan
from app.main import app
from app.modules.base import TARGET_DOMAIN, BaseModule
from app.schemas.analysis_response import AnalysisResponse
from app.schemas.module_result import ModuleResult
from app.services.scan_manager import ScanManager
from app.utils import networking

import app.services.scan_service as ss


def make_analysis(
    scan_id: str = "CS-2026-P5000001",
    target: str = "example.com",
    trust_score: int = 81,
    with_extra_module: bool = False,
) -> AnalysisResponse:
    modules = [
        {
            "module": "url_analysis",
            "status": "ok",
            "score": 62,
            "confidence": 95,
            "findings": [],
            "details": {
                "original_url": f"https://{target}",
                "normalized_url": f"https://{target}",
                "domain": target,
                "is_valid": True,
                "uses_https": True,
                "is_ip_address": False,
                "url_length": len(target),
                "subdomain_count": 1,
            },
        }
    ]
    if with_extra_module:
        modules.append(
            {
                "module": "infrastructure",
                "status": "ok",
                "score": 100,
                "confidence": 100,
                "findings": [],
                "details": {
                    "domain": target,
                    "infrastructure": {"asn": "AS15133", "status": "available"},
                    "resolved_ips": ["93.184.216.34"],
                },
            }
        )
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
        modules=modules,
        findings=[
            {
                "title": "Missing HSTS header",
                "severity": "medium",
                "description": "No Strict-Transport-Security header found.",
                "recommendation": "Add the HSTS header.",
            }
        ],
    )


class SpyPipeline:
    """Records every target the endpoint hands to the pipeline."""

    def __init__(self, result: AnalysisResponse, seen: list[str]) -> None:
        self.result = result
        self.seen = seen

    def run(self, target: str) -> AnalysisResponse:
        self.seen.append(target)
        return self.result


class BoundaryProbe(BaseModule):
    """A non-paying scanner that exercises the real validated-host boundary."""

    def __init__(self) -> None:
        super().__init__(
            name="probe",
            description="boundary probe",
            target_kind=TARGET_DOMAIN,
        )

    def run(self, target: str) -> ModuleResult:
        resolved, refused = networking.resolve_public_host(target)
        if refused:
            return ModuleResult(
                module="probe",
                status="error",
                score=0,
                confidence=0,
                details={"error": f"refused: {refused}"},
            )
        if resolved is None:
            return ModuleResult(
                module="probe",
                status="error",
                score=0,
                confidence=0,
                details={"error": "unresolvable"},
            )
        return ModuleResult(
            module="probe",
            status="ok",
            score=100,
            confidence=100,
            details={"resolved": list(resolved.addresses)},
        )


@pytest.fixture(autouse=True)
def clean_history():
    yield
    with SessionLocal() as session:
        session.execute(delete(Scan))
        session.commit()


@pytest.fixture
def client() -> TestClient:
    return TestClient(app)


@pytest.fixture
def private_boundary_targets() -> list[str]:
    return ["127.0.0.1", "[::1]", "2130706433", "0x7f000001", "localhost"]


def test_pipeline_receives_raw_target_unchanged(client, monkeypatch):
    seen: list[str] = []
    result = make_analysis()
    monkeypatch.setattr(ss, "ScanManager", lambda: SpyPipeline(result, seen))

    target = "https://user:pass@example.com/x"
    r = client.get(f"/scan/{target}")
    assert r.status_code == 200
    assert seen == [target]
    assert r.json() == result.model_dump(mode="json")

    seen.clear()
    r = client.post("/scan", json={"target": target})
    assert r.status_code == 200
    assert seen == [target]


def test_scan_route_returns_pipeline_result_verbatim(client, monkeypatch):
    result = make_analysis()
    monkeypatch.setattr(ss, "ScanManager", lambda: SpyPipeline(result, []))

    r = client.get("/scan/example.com")

    assert r.status_code == 200
    body = r.json()
    assert body == result.model_dump(mode="json")
    assert body["trust_score"] == 81
    assert body["confidence"] == 89
    assert body["verdict"] == "Low Risk"
    assert [f["title"] for f in body["findings"]] == ["Missing HSTS header"]
    assert body["modules"] == result.model_dump(mode="json")["modules"]


def test_history_echoes_scan_route_result_exactly(client, monkeypatch):
    result = make_analysis(scan_id="CS-2026-P5000002")
    monkeypatch.setattr(ss, "ScanManager", lambda: SpyPipeline(result, []))

    scan_body = client.get("/scan/example.com").json()
    h = client.get("/history/CS-2026-P5000002")

    assert h.status_code == 200
    assert h.json() == scan_body
    assert h.json() == result.model_dump(mode="json")


def test_infrastructure_is_informational_and_does_not_change_presentation(
    client, monkeypatch
):
    base = make_analysis()
    extra = make_analysis(with_extra_module=True)
    monkeypatch.setattr(ss, "ScanManager", lambda: SpyPipeline(base, []))
    a = client.get("/scan/example.com").json()
    monkeypatch.setattr(ss, "ScanManager", lambda: SpyPipeline(extra, []))
    b = client.get("/scan/example.com").json()

    assert (a["trust_score"], a["confidence"], a["verdict"]) == (
        b["trust_score"],
        b["confidence"],
        b["verdict"],
    ) == (81, 89, "Low Risk")
    assert [f["title"] for f in a["findings"]] == [f["title"] for f in b["findings"]]

    infra = next(m for m in b["modules"] if m["module"] == "infrastructure")
    assert infra["findings"] == []
    assert infra["score"] == 100
    assert infra["details"]["infrastructure"]["asn"] == "AS15133"


def test_endpoint_cannot_bypass_validated_host_boundary(
    client, monkeypatch, private_boundary_targets
):
    manager = ScanManager(modules=[BoundaryProbe()])
    monkeypatch.setattr(ss, "ScanManager", lambda: manager)

    for target in private_boundary_targets:
        r = client.get(f"/scan/{target}")
        assert r.status_code == 200
        probe = next(m for m in r.json()["modules"] if m["module"] == "probe")
        assert probe["status"] == "error"
        assert probe["score"] == 0
        assert probe["findings"] == []
        assert "refused" in probe["details"]["error"]


def test_rebinding_hostname_resolving_to_private_is_blocked(client, monkeypatch):
    manager = ScanManager(modules=[BoundaryProbe()])
    monkeypatch.setattr(ss, "ScanManager", lambda: manager)
    monkeypatch.setattr(
        networking.socket,
        "getaddrinfo",
        lambda host, *a, **k: [
            (socket.AF_INET, socket.SOCK_STREAM, 0, "", ("10.0.0.1", 0))
        ],
    )

    r = client.get("/scan/rebinding.example")

    assert r.status_code == 200
    probe = next(m for m in r.json()["modules"] if m["module"] == "probe")
    assert probe["status"] == "error"
    assert "private/reserved" in probe["details"]["error"]


def test_request_validation_rejects_bad_targets_without_hitting_pipeline(
    client, monkeypatch
):
    seen: list[str] = []
    result = make_analysis()
    monkeypatch.setattr(ss, "ScanManager", lambda: SpyPipeline(result, seen))

    r = client.get("/scan/" + "a" * 2049)
    assert r.status_code == 422
    assert seen == []

    r = client.post("/scan", json={"target": ""})
    assert r.status_code == 422
    assert seen == []

    r = client.post("/scan", json={"target": " " * 5})
    assert r.status_code == 200
    assert seen == ["     "]


def test_unexpected_internal_errors_are_controlled_without_leak(monkeypatch):
    def boom(self, target: str) -> AnalysisResponse:
        raise RuntimeError("SENSITIVE_INTERNAL_0x7fABCDEF")

    monkeypatch.setattr(ss.ScanManager, "run", boom)
    c = TestClient(app, raise_server_exceptions=False)

    r = c.get("/scan/example.com")

    assert r.status_code == 500
    assert r.text == "Internal Server Error"
    assert "SENSITIVE_INTERNAL_0x7fABCDEF" not in r.text
    assert "Traceback" not in r.text
    assert "RuntimeError" not in r.text


def test_no_credentials_leak_across_result_endpoints(client, monkeypatch):
    result = make_analysis(scan_id="CS-2026-P5000003", target="leak.example")
    monkeypatch.setattr(ss, "ScanManager", lambda: SpyPipeline(result, []))

    scan_resp = client.get("/scan/leak.example")
    assert scan_resp.status_code == 200
    bodies = [
        scan_resp.text,
        client.get("/history/CS-2026-P5000003").text,
        client.get("/reports/CS-2026-P5000003/json").text,
        client.get("/reports/CS-2026-P5000003/csv").text,
        client.get("/health").text,
    ]

    combined = "\n".join(bodies)
    for token in (
        "GOOGLE_SAFE_BROWSING_API_KEY",
        "VIRUS_TOTAL_API_KEY",
        "AI_API_KEY",
        "INFRASTRUCTURE_API_KEY",
        "CYBERSHIELD_DATABASE_URL",
        "api_key",
        "password",
        "authorization",
        "bearer",
        "sk-",
        "secret",
        "private_key",
    ):
        assert token.lower() not in combined.lower(), f"leaked token: {token}"


def test_export_json_contains_only_approved_public_fields(client, monkeypatch):
    result = make_analysis(scan_id="CS-2026-P5000004")
    monkeypatch.setattr(ss, "ScanManager", lambda: SpyPipeline(result, []))
    client.get("/scan/example.com")

    data = client.get("/reports/CS-2026-P5000004/json").json()

    assert set(data.keys()) == set(AnalysisResponse.model_fields.keys())


def test_export_filename_never_uses_target_or_traversal(client, monkeypatch):
    result = make_analysis(scan_id="CS-2026-P5000005", target="../secret/path.txt")
    monkeypatch.setattr(ss, "ScanManager", lambda: SpyPipeline(result, []))
    client.get("/scan/x")

    for fmt in ("json", "csv"):
        r = client.get(f"/reports/CS-2026-P5000005/{fmt}")
        assert r.status_code == 200
        disposition = r.headers.get("content-disposition", "")
        assert f"cybershield-CS-2026-P5000005.{fmt}" in disposition
        assert "secret" not in disposition
        assert ".." not in disposition
        assert "/" not in disposition.split("filename=")[1]


def test_read_result_endpoints_reject_unsupported_methods(client):
    assert client.delete("/scan/example.com").status_code == 405
    assert client.post("/history/CS-2026-NOPE").status_code == 405
    assert client.delete("/history/CS-2026-NOPE").status_code == 405
    assert client.post("/reports/CS-2026-NOPE/json").status_code == 405
    assert client.put("/reports/CS-2026-NOPE/csv").status_code == 405


def test_scan_history_export_carry_security_headers(client, monkeypatch):
    result = make_analysis(scan_id="CS-2026-P5000006")
    monkeypatch.setattr(ss, "ScanManager", lambda: SpyPipeline(result, []))

    responses = [
        client.get("/scan/example.com"),
        client.get("/history/CS-2026-P5000006"),
        client.get("/reports/CS-2026-P5000006/json"),
    ]
    for r in responses:
        assert r.status_code == 200
        for header in (
            "x-frame-options",
            "x-content-type-options",
            "referrer-policy",
        ):
            assert r.headers.get(header), header