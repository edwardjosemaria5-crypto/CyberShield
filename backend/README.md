# CyberShield Backend

This backend follows the app-centric structure:

- app/api/routes
- app/core
- app/modules
- app/models
- app/schemas
- app/services
- app/utils

## External Threat Intelligence Providers

The `threatintel` module runs local heuristics (phishing keywords, malware
patterns, static blacklist feeds) and — when configured — queries external
provider APIs through a normalized adapter layer.

### Architecture

```
scanner.scan_threatintel_module(domain, adapters=None)   # local heuristics always run
  └─ adapters: list[ThreatIntelAdapter]                  # injected by service layer or tests
       └─ adapter.lookup(target) -> ThreatIntelSignals   # canonical contract (schemas/threat_intel.py)
```

- `app/modules/threatintel/adapters/base.py` — abstract `ThreatIntelAdapter`
  contract. Every provider implements `lookup(target) -> ThreatIntelSignals`.
- `app/modules/threatintel/adapters/google_safe_browsing.py` — first concrete
  provider (Google Safe Browsing v4 `threatMatches:list`).
- `app/modules/threatintel/adapters/virustotal.py` — second concrete provider
  (VirusTotal v3 `GET /urls/{id}`). Detection counts drive an
  evidence-derived confidence (see below); no retries are implemented.
- `app/modules/threatintel/adapters/__init__.py` — `build_adapters(...)`
  factory; only instantiates providers that are configured (API key set).
- `app/schemas/threat_intel.py` — the canonical signal contract:
  `provider`, `status` (`available`/`unavailable`), `reason`, `malicious`,
  `suspicious`, `detections`, `categories`, `confidence`, `evidence`,
  `timestamp`.

### Contract rules (enforced by tests)

- A provider check that fails is a **missing data point, never a verdict**:
  every failure path returns `status="unavailable"` with a reason
  (`timeout`, `rate_limited`, `unauthorized`, `bad_response`,
  `no_analysis`, ...). The adapter never raises for network/provider errors.
- VirusTotal answering `404 ResourceNotFoundException` (no analysis record
  exists for the URL) maps to `unavailable`/`no_analysis` — absence of a
  record is explicitly NOT reported as a clean verdict.
- Unavailable signals add no penalty. Only available signals carrying a
  verdict (`malicious=True`/`suspicious=True`) reduce the module score.
- Provider penalties (see `modules/threatintel/rules.py`) are aggregated and
  capped (`PROVIDER_PENALTY_CAP = 40`) so external data can never single-
  handedly zero out a domain.
- The scanner signature is test-friendly: `scan_threatintel_module(domain,
  adapters=[...])` lets tests inject fake adapters without network access.

### Multi-provider correlation

When multiple providers are configured, the module reconciles every signal
through a **provider-independent correlation engine**
(`app/modules/threatintel/correlation.py`) that never imports adapter code
and never switches on provider names:

```
adapters  ->  ThreatIntelSignals[]  ->  correlate_threat_signals()  ->  CorrelationResult

ModuleResult
  ├── aggregate finding        "2 of 2 provider(s) reported the target as malicious."
  └── per-provider findings    original evidence, provenance preserved
```

- `agreement` is `consistent` / `partial` / `conflict` / `none`, computed
  only among **available** providers. An unavailable provider is never a
  dissenting vote: `conflict` means *malicious + clean* specifically;
  suspicious + clean is only `partial`.
- Aggregated confidence is NOT an average. It starts from the strongest
  flagging signal, adds `THREAT_INTEL_AGREEMENT_BONUS` per extra agreeing
  provider, and applies `THREAT_INTEL_CONFLICT_MULTIPLIER` when providers
  conflict -- then clamps to [0, 100]. These are initial tuning values
  (documented in `correlation.py`), configurable and bounded by tests.
- If providers carry `confidence == 0` we never guess: the correlated
  confidence stays 0.
- The aggregate finding **supplements**, never replaces, the provider
  findings -- the module's `details["threat_intel_correlation"]` keeps the
  full correlation picture alongside `details["external_threat_intel"]`.

### Confidence behavior

Google Safe Browsing ships an **implied default** confidence (90 for a
match, 10 when no match). VirusTotal ships no confidence value at all, so
its adapter derives one **from engine counts** (evidence-derived, documented
in the adapter):

```
confidence = 0                               if no flagged engines
confidence = min(100, 30 + 15*malicious + 10*suspicious)  otherwise
```

Both arrive at the correlation layer as the same normalized `confidence`
field; the engine never knows (nor cares) whether a number was
provider-declared or evidence-derived. A future refactor could tag the
*origin* of a confidence value without touching the correlation algorithm.
A 0-confidence verdict never fabricates certainty and contributes no
provider penalty.

### Configuration

Read from the environment in `app/core/config.py`; no secrets are ever
logged or stored. See `.env.example`.

| Variable | Default | Purpose |
| --- | --- | --- |
| `CYBERSHIELD_THREAT_PROVIDER_ENABLED` | `true` | Master switch for all external provider lookups |
| `GOOGLE_SAFE_BROWSING_API_KEY` | (empty) | Safe Browsing API key; when empty the provider is skipped |
| `GOOGLE_SAFE_BROWSING_TIMEOUT_SECONDS` | `5.0` | Per-request timeout for provider lookups |
| `VIRUS_TOTAL_API_KEY` | (empty) | VirusTotal v3 key; when empty the provider is skipped |
| `VIRUS_TOTAL_TIMEOUT_SECONDS` | `8.0` | Per-request timeout for VirusTotal lookups |
| `THREAT_INTEL_AGREEMENT_BONUS` | `10` | Confidence points added per extra agreeing provider (0-100, clamped) |
| `THREAT_INTEL_CONFLICT_MULTIPLIER` | `0.85` | Confidence dampener for conflicting verdicts (0.0-1.0, clamped) |

**VirusTotal rate limits (free tier):** ~4 requests/minute and ~500
requests/day. CyberShield issues one request per scanned URL, never retries,
and fails over to an unavailable signal on `429` — keep scan usage
user-paced.

### Testing

Mocked tests live in `tests/test_threat_intel_adapters.py` (Google Safe
Browsing), `tests/test_threat_intel_virustotal.py` (VirusTotal adapter +
two-provider correlation), `tests/test_threat_intel_correlation.py` and
`tests/test_threat_intel_confidence.py`. All external calls use
`httpx.MockTransport` injected through the adapter constructor — no network,
no real keys. Run the whole backend suite from the `backend/` directory with
(the virtual environment lives at the repository root):

```sh
..\.venv\Scripts\python.exe -m pytest        # Windows
../.venv/bin/python -m pytest                # macOS / Linux
```

### Adding a new provider

1. Create `app/modules/threatintel/adapters/<provider>.py` implementing
   `ThreatIntelAdapter.lookup()`; map every failure onto an `unavailable`
   signal with a canonical `reason` (extend the `UnavailableReason` literal
   only when a genuinely new state is needed).
2. Normalize its verdict fields into `ThreatIntelSignals` (validate all
   external data; unknown labels → `unknown`). If the provider reports no
   confidence, derive one from its actual evidence and document the formula,
   or keep 0.
3. Register in `adapters/__init__.py` `build_adapters()` with config keys in
   `config.py` + `.env.example`.
4. Add mocked tests mirroring `test_threat_intel_virustotal.py`.

## AI Security Explanation (presentation layer)

`ai_explanation` is an optional, best-effort, user-facing prose explanation
of a completed report. It is strictly **presentation**: it never touches
scoring, and the rest of the pipeline (Risk Engine, scanners, threat-intel
correlation, save/history) works identically with AI on, off, or broken.

### Invariants (enforced by `tests/test_ai_explanation.py`)

- **Deterministic authority.** With or without AI, `AnalysisResponse` —
  trust score, confidence, verdict, modules, findings, summary — is
  byte-identical. `ai_explanation` is a nullable sidecar set on a copy
  (`model_copy`) of the completed response.
- **A scan never fails because of AI.** Disabled, unconfigured provider,
  timeout, HTTP/rate-limit errors, malformed output and schema violation all
  degrade to `ai_explanation=null`. Exactly one provider attempt per scan
  (no retries), bounded by `AI_TIMEOUT_SECONDS`.
- **Score-blind evidence.** The evidence package built for the model
  (`modules/ai_explanation/evidence.py`) is an allowlist that deliberately
  excludes the trust score, confidence and verdict — the model never sees or
  restates risk-engine numbers. Raw module `details`, credentials and API
  keys are never copied in; findings are capped (`MAX_FINDINGS`) and long
  strings clipped (`MAX_EVIDENCE_LEN`).
- **Strict schema.** Before anything is stored or rendered, the model output
  is validated against `AIExplanation` (all fields required, bounded strings,
  1-12 factors/actions). Invalid or partial output is discarded wholesale.
- **No secret handling.** Keys travel environment → provider request header
  only, never logged (provider logs exception *classes*, not objects).

### Architecture

```
run_scan()                       services/scan_service.py
  ├─ ScanManager().run()        deterministic pipeline (unchanged)
  └─ AIExplanationService().generate(analysis)   — never raises, never scores
       ├─ build_evidence()      allowlist, score-blind package
       ├─ provider.generate()   one OpenAI-compatible chat request
       └─ AIExplanation.model_validate(strict) → sidecar or null
```

- `app/modules/ai_explanation/base.py` — `AIExplanationProvider` contract
  (`generate(evidence) -> dict | None`, `is_configured`).
- `app/modules/ai_explanation/providers/openai_compatible.py` — concrete
  adapter for any OpenAI-compatible `POST /chat/completions` endpoint
  (OpenAI, gateways, local servers) using the existing `httpx` dependency.
- `app/modules/ai_explanation/evidence.py` — evidence package builder.
- `app/modules/ai_explanation/prompts.py` — static system prompt; scan data
  is always delivered in the *user* message so evidence cannot overwrite
  the rules.
- `app/schemas/ai_explanation.py` — validated output contract (no score /
  verdict fields by design).
- `app/services/ai_explanation_service.py` — orchestrator; every failure
  path logs and returns the untouched analysis.

### Configuration

| Variable | Default | Purpose |
| --- | --- | --- |
| `AI_ENABLED` | `false` | Master switch for the explanation layer |
| `AI_PROVIDER` | `openai-compatible` | Provider name; unknown names resolve to disabled |
| `AI_MODEL` | `gpt-4o-mini` | Model id sent to the endpoint |
| `AI_API_KEY` | (empty) | Key (env-only); when empty the layer stands down |
| `AI_BASE_URL` | `https://api.openai.com/v1` | Base URL of an OpenAI-compatible API |
| `AI_TIMEOUT_SECONDS` | `30.0` | Per-request timeout |
| `AI_MAX_TOKENS` | `800` | Output cap |

### Adding a new AI provider

Implement `AIExplanationProvider` in `providers/<name>.py` (return parsed
output dicts or `None`; never raise for provider problems), register it in
`providers/__init__.py` `build_provider()`, add its config keys, and mirror
the mocked tests (`httpx.MockTransport` via the provider `transport`
argument — no network, no real keys).