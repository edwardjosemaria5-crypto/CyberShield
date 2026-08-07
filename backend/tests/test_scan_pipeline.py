"""Tests for the scan pipeline: scan IDs, registry, ScanManager, risk engine."""

import asyncio
import time

from app.core.scan_ids import generate_scan_id
from app.modules.base import BaseModule, TARGET_DOMAIN, TARGET_URL
from app.modules.registry import MODULE_REGISTRY, get_module_registry
from app.risk_engine.engine import calculate_risk_score, severity_summary
from app.risk_engine.scorer import compute_confidence
from app.schemas.finding import Finding
from app.schemas.module_result import ModuleResult
from app.services.scan_manager import ScanManager


class FakeModule(BaseModule):
    """Deterministic scanner stub for pipeline tests."""

    def __init__(self, name, target_kind=TARGET_DOMAIN, score=100, confidence=100,
                 findings=None, fail=False, delay=0.0):
        super().__init__(name=name, description=f"stub {name}", target_kind=target_kind)
        self._score = score
        self._confidence = confidence
        self._findings = findings or []
        self._fail = fail
        self._delay = delay

    def run(self, target):
        if self._delay:
            time.sleep(self._delay)
        if self._fail:
            raise RuntimeError(f"{self.name} exploded")
        return ModuleResult(
            module=self.name,
            score=self._score,
            confidence=self._confidence,
            findings=[f.model_copy() for f in self._findings],
        )


def make_manager(modules):
    return ScanManager(modules=modules)


# ---------------------------------------------------------------- scan ids

def test_scan_id_format():
    scan_id = generate_scan_id()

    parts = scan_id.split("-")
    assert parts[0] == "CS"
    assert len(parts[1]) == 4 and parts[1].isdigit()
    assert len(parts[2]) == 8
    assert scan_id == scan_id.upper()


def test_scan_ids_are_unique():
    ids = {generate_scan_id() for _ in range(5000)}
    assert len(ids) == 5000


# ---------------------------------------------------------------- registry

def test_registry_contains_expected_modules_in_pipeline_order():
    names = [m.name for m in MODULE_REGISTRY]

    assert names[0] == "url_analysis"
    for expected in [
        "reputation", "whois", "dns", "ssl", "headers",
        "typosquatting", "threatintel", "blacklist", "phishing",
    ]:
        assert expected in names
    assert len(names) == len(set(names)), "module names must be unique"


def test_registry_scanners_are_base_modules():
    assert all(isinstance(m, BaseModule) for m in MODULE_REGISTRY)
    assert all(m.target_kind in {TARGET_URL, TARGET_DOMAIN} for m in MODULE_REGISTRY)
    assert len(get_module_registry()) == len(MODULE_REGISTRY)


# ---------------------------------------------------------------- ScanManager

def test_scan_manager_returns_full_response():
    modules = [
        FakeModule("url_analysis", target_kind=TARGET_URL, score=100, confidence=100),
        FakeModule("whois", score=100, confidence=100),
        FakeModule("dns", score=100, confidence=100),
        FakeModule(
            "headers",
            score=80,
            confidence=90,
            findings=[Finding(title="Missing HSTS", severity="medium", description="no HSTS")],
        ),
    ]
    response = make_manager(modules).run("example.com")

    assert response.scan_id.startswith("CS-")
    assert response.target == "example.com"
    assert response.normalized_url == "https://example.com"
    assert response.domain == "example.com"
    assert response.started_at and response.completed_at
    assert 0 <= response.trust_score <= 100
    assert 0 <= response.confidence <= 100
    assert response.verdict.value
    assert [m.module for m in response.modules] == [
        "url_analysis", "whois", "dns", "headers",
    ]
    assert response.summary.medium == 1
    assert response.summary.critical == response.summary.high == 0
    assert any(f.title == "Missing HSTS" for f in response.findings)


def test_scan_manager_runs_domain_modules_concurrently():
    modules = [
        FakeModule("url_analysis", target_kind=TARGET_URL, delay=0.05),
        FakeModule("whois", delay=0.25),
        FakeModule("dns", delay=0.25),
    ]
    started = time.monotonic()
    response = make_manager(modules).run("example.com")
    elapsed = time.monotonic() - started

    assert len(response.modules) == 3
    assert elapsed < 0.5, f"modules ran sequentially (took {elapsed:.2f}s)"


def test_scan_manager_survives_module_failure():
    modules = [
        FakeModule("url_analysis", target_kind=TARGET_URL),
        FakeModule("whois", fail=True),
        FakeModule("dns", score=100, confidence=100),
    ]
    response = make_manager(modules).run("example.com")

    assert response.scan_id.startswith("CS-")
    assert response.trust_score > 0
    by_name = {m.module: m for m in response.modules}
    assert by_name["whois"].status == "error"
    assert by_name["dns"].status == "ok"


def test_scan_manager_invalid_target_runs_structural_scan_only():
    modules = [
        FakeModule("url_analysis", target_kind=TARGET_URL, score=60, confidence=100),
        FakeModule("whois"),
    ]
    response = make_manager(modules).run("/no-host")

    assert [m.module for m in response.modules] == ["url_analysis"]
    assert response.domain == ""
    assert response.scan_id.startswith("CS-")


def test_scan_manager_arun_matches_run():
    modules = [
        FakeModule("url_analysis", target_kind=TARGET_URL),
        FakeModule("dns"),
    ]
    manager = make_manager(modules)
    sync_result = manager.run("example.com")
    async_result = asyncio.run(manager.arun("example.com"))

    assert async_result.trust_score == sync_result.trust_score
    assert async_result.domain == sync_result.domain


# ---------------------------------------------------------------- risk engine

def test_engine_computes_severity_summary():
    findings = [
        Finding(title="a", severity="critical"),
        Finding(title="b", severity="high"),
        Finding(title="c", severity="medium"),
        Finding(title="d", severity="low"),
        Finding(title="e", severity="info"),
        Finding(title="f", severity="medium"),
    ]
    summary = severity_summary(findings)

    assert summary.critical == 1
    assert summary.high == 1
    assert summary.medium == 2
    assert summary.low == 1
    assert summary.info == 1


def test_engine_sorts_findings_by_severity():
    results = {
        "dns": ModuleResult(
            module="dns",
            findings=[Finding(title="low one", severity="low")],
        ),
        "headers": ModuleResult(
            module="headers",
            findings=[Finding(title="critical one", severity="critical")],
        ),
    }
    response = calculate_risk_score(results)

    assert [f.title for f in response.findings] == ["critical one", "low one"]


def test_confidence_is_weighted_average():
    results = {
        "url_analysis": ModuleResult(module="url_analysis", score=100, confidence=100),
        "dns": ModuleResult(module="dns", score=100, confidence=50),
    }
    confidence = compute_confidence(results)

    expected = round((20 * 100 + 10 * 50) / 30)
    assert confidence == expected


def test_confidence_penalizes_errored_modules():
    results = {
        "dns": ModuleResult(module="dns", score=100, confidence=100),
        "headers": ModuleResult(module="headers", status="error", score=0, confidence=0),
    }
    confidence = compute_confidence(results)

    assert 0 < confidence < 100