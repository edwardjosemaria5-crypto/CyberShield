"""Tests for the AI security-explanation layer.

Coverage matrix:

- Provider adapter (httpx MockTransport): success, timeout, HTTP errors,
  rate limiting, malformed payloads, unconfigured provider.
- Evidence package: deterministic, allowlisted, secrets excluded,
  score/verdict-blind, caps applied.
- Service: best-effort semantics — never raises, never mutates the
  deterministic analysis, strict schema validation of model output.
- Critical invariant: the deterministic analysis (score, verdict, modules,
  findings, confidence, summary) is identical with or without AI success.
- run_scan integration: the AI layer is a pure sidecar and is persisted
  alongside the deterministic snapshot.
"""

import json

import httpx
import pytest

from app.modules.ai_explanation.evidence import MAX_EVIDENCE_LEN, MAX_FINDINGS, build_evidence
from app.modules.ai_explanation.base import AIExplanationProvider
from app.modules.ai_explanation.providers.openai_compatible import OpenAICompatibleProvider
from app.modules.ai_explanation.prompts import SYSTEM_PROMPT
from app.schemas.ai_explanation import AIExplanation
from app.schemas.analysis_response import AnalysisResponse
from app.schemas.finding import Finding
from app.schemas.module_result import ModuleResult
from app.schemas.summary import SeveritySummary
from app.schemas.verdict import Verdict
from app.services.ai_explanation_service import AIExplanationService
from app.services.scan_service import run_scan

# ----------------------------------------------------------------------
# fixtures / helpers
# ----------------------------------------------------------------------

VALID_EXPLANATION = {
    "summary": "The evidence indicates moderate risk with notable findings.",
    "why_risky": "The headers module reported missing security headers.",
    "key_risk_factors": ["Missing HSTS header"],
    "technical_explanation": "HTTP headers omit HSTS; browsers reduce protection.",
    "recommended_actions": ["Enable HSTS"],
}


def make_provider(*, result=None, error=None, configured=True):
    """Duck-typed provider — must look like the AIExplanationProvider ABC."""

    class FakeProvider(AIExplanationProvider):
        def __init__(self):
            super().__init__(api_key="fake-key", model="fake-model")
            self.calls = 0
            self.seen_evidence = None

        @property
        def is_configured(self):
            return configured

        def generate(self, evidence):
            self.calls += 1
            self.seen_evidence = evidence
            if error is not None:
                raise error
            return result

    return FakeProvider()


def make_analysis(**overrides) -> AnalysisResponse:
    """Deterministic, fixed analysis for invariant comparisons."""
    base = AnalysisResponse(
        scan_id="CS-2026-00000001",
        target="example.com",
        normalized_url="https://example.com",
        domain="example.com",
        started_at="2026-08-08T10:00:00Z",
        completed_at="2026-08-08T10:00:02Z",
trust_score=74,
            confidence=88,
            verdict=Verdict.MODERATE_RISK,
        summary=SeveritySummary(critical=1, high=1, medium=2, low=1, info=1),
        modules=[
            ModuleResult(
                module="url_analysis",
                score=100,
                confidence=100,
                findings=[Finding(title="url ok", severity="info")],
            ),
            ModuleResult(
                module="headers",
                score=50,
                confidence=70,
                findings=[
                    Finding(
                        title="Missing HSTS",
                        severity="medium",
                        description="The HSTS header is absent.",
                        evidence="header-missing:hsts",
                    )
                ],
            ),
            ModuleResult(
                module="threatintel",
                score=61,
                confidence=90,
                details={
                    "threat_intel_correlation": {
                        "available_count": 2,
                        "malicious_count": 1,
                        "suspicious_count": 0,
                        "clean_count": 1,
                        "unavailable_count": 0,
                        "agreement": "partial",
                        "consensus": "contested",
                        "conflict": True,
                        "malicious_confidence": 55,
                        "suspicious_confidence": 0,
                        "signals": [
                            {"provider": "google", "status": "ok", "malicious": True}
                        ],
                    },
                    "secret_api_key": "sk-12345",
                },
            ),
        ],
        findings=[
            Finding(title="Missing HSTS", severity="medium"),
            Finding(title="Suspicious redirect", severity="high"),
        ],
    )
    return base.model_copy(update=overrides)


def _deterministic_dump(analysis: AnalysisResponse) -> dict:
    """Serialize the analysis excluding the AI sidecar."""
    data = analysis.model_dump()
    data.pop("ai_explanation", None)
    return data


deterministic_dump = _deterministic_dump


# --------------------------------------------------------------------------
# evidence package
# --------------------------------------------------------------------------

def test_evidence_package_shape_and_allowlist():
    evidence = build_evidence(make_analysis())
    top_level = set(evidence)
    assert top_level == {
        "target", "normalized_url", "domain",
        "severity_counts", "modules", "findings", "threat_intel",
    }
    assert "trust_score" not in evidence
    assert "confidence" not in evidence
    assert "verdict" not in evidence


def test_evidence_is_score_verdict_blind():
    evidence = build_evidence(make_analysis(trust_score=9, verdict=Verdict.CRITICAL, confidence=3))
    payload = json.dumps(evidence, default=str)
    assert "trust_score" not in payload
    assert '"verdict"' not in payload
    assert "verdict" not in payload


def test_evidence_is_deterministic():
    a = build_evidence(make_analysis())
    b = build_evidence(make_analysis())
    assert json.dumps(a, sort_keys=True, default=str) == json.dumps(b, sort_keys=True, default=str)


def test_evidence_caps_findings_and_clips_long_text():
    long_desc = ("x" * 1000) + "END"
    analysis = make_analysis(
        findings=[
            Finding(title=f"f{i}", severity="low", description=long_desc)
            for i in range(30)
        ]
    )
    evidence = build_evidence(analysis)
    assert len(evidence["findings"]) == MAX_FINDINGS
    clipped = evidence["findings"][0]["description"]
    assert len(clipped) <= MAX_EVIDENCE_LEN
    assert clipped.endswith("...")


def test_evidence_secrets_excluded():
    """Raw module details (with secrets) must never reach the model."""
    evidence = build_evidence(make_analysis())
    payload = json.dumps(evidence, default=str)
    assert "secret_api_key" not in payload
    assert "sk-12345" not in payload
    assert "secure:" not in payload


def test_evidence_threat_intel_is_allowlisted_correlation_only():
    evidence = build_evidence(make_analysis())
    ti = evidence["threat_intel"]
    assert ti["available_count"] == 2
    assert ti["malicious_count"] == 1
    assert ti["conflict"] is True
    assert [s["provider"] for s in ti["signals"]] == ["google"]
    assert set(ti) <= {
        "available_count", "malicious_count", "suspicious_count", "clean_count",
        "unavailable_count", "agreement", "consensus", "conflict",
        "malicious_confidence", "suspicious_confidence", "signals",
    }


def test_evidence_minimal_analysis_ok():
    analysis = AnalysisResponse(
        target="x.example", normalized_url="https://x.example", domain="x.example"
    )
    evidence = build_evidence(analysis)
    assert evidence["modules"] == []
    assert evidence["findings"] == []
    assert evidence["threat_intel"] is None


def test_evidence_threat_intel_none_when_module_missing():
    analysis = make_analysis(modules=[ModuleResult(module="dns")])
    assert build_evidence(analysis)["threat_intel"] is None


# --------------------------------------------------------------------------
# provider adapter (httpx mocked)
# --------------------------------------------------------------------------


def _mocked_provider(handler, api_key=None):
    return OpenAICompatibleProvider(
        api_key=api_key or "fake-key",
        base_url="https://provider.example/v1",
        transport=httpx.MockTransport(handler),
    )


def _chat_response(content):
    return {"choices": [{"message": {"role": "assistant", "content": content}}]}


def test_provider_parses_valid_json():
    def handler(request):
        assert request.url == "https://provider.example/v1/chat/completions"
        assert request.headers["Authorization"] == "Bearer secret-key"
        body = json.loads(request.content)
        assert body["model"] == "gpt-4o-mini"
        assert body["response_format"] == {"type": "json_object"}
        assert body["messages"][0]["role"] == "system"
        assert SYSTEM_PROMPT in body["messages"][0]["content"]
        assert "evidence" in body["messages"][1]["content"]
        return httpx.Response(200, json=_chat_response(json.dumps(VALID_EXPLANATION)))

    provider = _mocked_provider(handler, api_key="secret-key")
    out = provider.generate({"m": 1})
    assert out == VALID_EXPLANATION


def test_provider_timeout_returns_none():
    def handler(request):
        raise httpx.ConnectTimeout("cancelled")

    provider = _mocked_provider(handler)
    assert provider.generate({}) is None


def test_provider_rate_limited_returns_none():
    def handler(request):
        return httpx.Response(429, json={"error": "slow down"})

    provider = _mocked_provider(handler)
    assert provider.generate({}) is None


def test_provider_server_errors_return_none():
    def handler(request):
        return httpx.Response(503, json={"error": "boom"})

    provider = _mocked_provider(handler)
    assert provider.generate({}) is None


def test_provider_rejects_api_key_errors():
    def handler(request):
        return httpx.Response(401, json={"error": "unauthorized"})

    provider = _mocked_provider(handler)
    assert provider.generate({}) is None


def test_provider_malformed_payloads_return_none():
    bodies = [
        {"choices": [{"message": {"content": "not json"}}]},
        {"choices": [{"message": {"content": "[1, 2]"}}]},
        {"choices": [{"message": {"content": ""}}]},
        {},
        {"choices": "nope"},
        {"choices": [{"message": {"content": None}}]},
    ]
    for body in bodies:
        provider = _mocked_provider(
            lambda request, body=body: httpx.Response(200, json=body)
        )
        assert provider.generate({}) is None, f"expected None for {body}"


def test_provider_unconfigured_never_calls_api():
    provider = OpenAICompatibleProvider(api_key=None, transport=httpx.MockTransport(
        lambda r: (_ for _ in ()).throw(AssertionError("must not be called"))
    ))
    assert provider.is_configured is False
    assert provider.generate({}) is None


# --------------------------------------------------------------------------
# service — best-effort, invariant safe
# --------------------------------------------------------------------------


def test_service_disabled_is_noop():
    analysis = make_analysis()
    service = AIExplanationService(provider=make_provider(), enabled=False)
    out = service.generate(analysis)
    assert deterministic_dump(out) == deterministic_dump(analysis)
    assert out.ai_explanation is None


def test_service_unconfigured_is_noop():
    analysis = make_analysis()
    service = AIExplanationService(provider=make_provider(configured=False), enabled=True)
    out = service.generate(analysis)
    assert out.ai_explanation is None
    assert deterministic_dump(out) == deterministic_dump(analysis)


def test_service_attaches_valid_explanation():
    provider = make_provider(result=VALID_EXPLANATION)
    analysis = make_analysis()
    out = AIExplanationService(provider=provider, enabled=True).generate(analysis)
    assert provider.calls == 1
    assert out.ai_explanation is not None
    assert out.ai_explanation.summary == VALID_EXPLANATION["summary"]
    assert out.ai_explanation.generated_by == "ai-external"


def test_service_null_provider_output_is_noop():
    analysis = make_analysis()
    out = AIExplanationService(provider=make_provider(result=None), enabled=True).generate(analysis)
    assert out.ai_explanation is None


def test_service_provider_error_is_noop():
    analysis = make_analysis()
    service = AIExplanationService(provider=make_provider(error=RuntimeError("boom")), enabled=True)
    out = service.generate(analysis)
    assert out.ai_explanation is None
    assert out.trust_score == analysis.trust_score


def test_service_rejects_malformed_output():
    cases = [
        "just a string",
        ["array", "not", "object"],
        {"summary": "missing every other key"},
        {"summary": "", "why_risky": "x", "key_risk_factors": ["a"],
         "technical_explanation": "x", "recommended_actions": ["a"]},
        {"summary": "s", "why_risky": "x", "key_risk_factors": [], 
         "technical_explanation": "x", "recommended_actions": ["a"]},
        {"summary": "s", "why_risky": "x", "key_risk_factors": ["a"],
         "technical_explanation": "x", "recommended_actions": [1, 2]},
    ]
    for bad in cases:
        analysis = make_analysis()
        service = AIExplanationService(provider=make_provider(result=bad), enabled=True)
        out = service.generate(analysis)
        assert out.ai_explanation is None, f"expected None for {bad}"
        assert deterministic_dump(out) == deterministic_dump(analysis)


def test_service_accepts_extra_unknown_keys():
    extra = dict(VALID_EXPLANATION, unsupported_field="whatever")
    analysis = make_analysis()
    out = AIExplanationService(provider=make_provider(result=extra), enabled=True).generate(analysis)
    assert out.ai_explanation is not None


def test_service_invariant_identical_with_and_without_ai():
    analysis = make_analysis()
    plain = AIExplanationService(provider=make_provider(result=VALID_EXPLANATION), enabled=False).generate(analysis)
    enhanced = AIExplanationService(provider=make_provider(result=VALID_EXPLANATION), enabled=True).generate(analysis)
    assert enhanced.ai_explanation is not None
    assert deterministic_dump(plain) == deterministic_dump(enhanced)


def test_service_only_one_attempt():
    provider = make_provider(result=VALID_EXPLANATION)
    out = AIExplanationService(provider=provider, enabled=True).generate(make_analysis())
    assert provider.calls == 1


# --------------------------------------------------------------------------
# run_scan integration
# --------------------------------------------------------------------------


class _StaticScanManager:
    def __init__(self, analysis):
        self._analysis = analysis

    def run(self, domain):
        return self._analysis.model_copy(deep=True)


def _patch_manager(monkeypatch, analysis):
    monkeypatch.setattr("app.services.scan_service.ScanManager", lambda: _StaticScanManager(analysis))


@pytest.fixture(scope="module", autouse=True)
def _db_tables():
    """Ensure the test database schema exists before persistence tests."""
    from app.database.connection import init_db

    init_db()
    yield


def test_run_scan_with_ai_success(monkeypatch):
    analysis = make_analysis()
    _patch_manager(monkeypatch, analysis)
    provider = make_provider(result=VALID_EXPLANATION)
    out = run_scan("example.com", explainer=AIExplanationService(provider=provider, enabled=True).generate)
    assert out.ai_explanation is not None
    assert provider.seen_evidence["domain"] == "example.com"
    assert len(provider.seen_evidence["findings"]) == 2


def test_run_scan_with_ai_failure_is_successful_scan(monkeypatch):
    analysis = make_analysis()
    _patch_manager(monkeypatch, analysis)
    provider = make_provider(result=None)
    out = run_scan("example.com", explainer=AIExplanationService(provider=provider, enabled=True).generate)
    assert out.ai_explanation is None
    assert out.trust_score == analysis.trust_score
    assert out.verdict == analysis.verdict


def test_run_scan_with_ai_disabled_is_successful_scan(monkeypatch):
    analysis = make_analysis()
    _patch_manager(monkeypatch, analysis)
    out = run_scan("example.com")
    assert out.ai_explanation is None
    assert out.trust_score == analysis.trust_score


def test_run_scan_persists_ai_explanation(monkeypatch):
    from app.services.history_service import get_scan
    analysis = make_analysis()
    _patch_manager(monkeypatch, analysis)
    provider = make_provider(result=VALID_EXPLANATION)
    out = run_scan("example.com", explainer=AIExplanationService(provider=provider, enabled=True).generate)
    stored = get_scan(out.scan_id)
    assert stored is not None
    assert stored.ai_explanation is not None
    assert stored.ai_explanation.summary == VALID_EXPLANATION["summary"]
    assert stored.trust_score == analysis.trust_score


def test_run_scan_without_ai_default_persists_deterministic(monkeypatch):
    from app.services.history_service import get_scan

    analysis = AnalysisResponse(
        target="u.example", normalized_url="https://u.example", domain="u.example"
    )
    _patch_manager(monkeypatch, analysis)
    out = run_scan("u.example")
    stored = get_scan(out.scan_id)
    assert stored.ai_explanation is None
    assert stored.domain == "u.example"