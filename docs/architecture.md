# CyberShield — Architecture

This document describes how CyberShield v1 actually works, based on the current
codebase (`backend/`, `frontend/`, `docker-compose.yml`). It is the technical
companion to the [`README`](../README.md) and is written to be accurate to the
implementation rather than aspirational.

---

## 1. System Overview

CyberShield is a full-stack website security assessment platform. A user submits
a domain or URL; the backend runs a pipeline of independent analysis modules,
aggregates their evidence into a deterministic 0–100 Trust Score with a verdict
and confidence, attaches evidence-backed findings, and (optionally) adds an AI
explanation that never influences scoring. Every completed scan is persisted and
can be exported as JSON, CSV or PDF.

```
┌────────────┐      HTTP        ┌─────────────────────────┐     external
│  Frontend  │ ───────────────► │  Backend (FastAPI)      │     providers
│  React SPA │  http://…:8000   │  app/                   │   (optional)
│  (nginx :80)│ ◄─────────────── │  - api/routes (HTTP)    │   Google Safe
└────────────┘     JSON/Blob    │  - services (orchestration)│  Browsing v4
                                │  - modules (scanners)     │   VirusTotal v3
                                │  - risk_engine (scoring)  │   OpenAI-compatible
                                │  - database (SQLite/SQLA) │   (AI, optional)
                                └─────────────────────────┘
                                       │ SQLite file (persisted via Docker volume)
                                       ▼
                              ./data/cybershield.db
```

Key properties (each enforced by the test suite):

- The pipeline is **deterministic**: the Risk Engine alone computes the Trust
  Score, confidence and verdict. The AI layer can neither read nor influence
  those numbers.
- Modules are **isolated**: one failing scanner becomes an `error` module result
  and can never abort or poison the rest of the scan.
- **Unavailable evidence is not malicious**: failed WHOIS, failed providers, or
  a 404 from VirusTotal become informational signals with zero penalty, never
  security findings.
- Persistence is **best-effort**: a storage failure never changes the response
  the user receives.

## 2. Frontend Architecture

Location: `frontend/` — React 19, Vite 8, React Router 7, axios.

- **API base URL** is compiled in at build time from `VITE_API_BASE_URL`
  (`src/services/api.js`); the Docker build passes `http://localhost:8000`.
  All requests go through one axios instance (`src/services/api.js`) with a
  120 s timeout and an interceptor that normalizes backend `detail` errors.
- **Data layer** (`src/services/scanService.js`): `runScan`, `scanModule`,
  `getHistory`, `getScanReport`, `exportReport` (blob response for downloads).
- **State** (`src/context/ScanProvider.jsx`, `src/hooks/useScan.js`): the scan
  lifecycle (idle → scanning → success/error) is shared via React context so
  Home and Scan both trigger scans and Dashboard renders the result.
- **Routing** (`src/App.jsx`): `/` (Home), `/scan`, `/dashboard`,
  `/history`, `/report/:scanId` (Report page, keyed by scan id), `/settings`
  (placeholder), and a catch-all redirect to `/`.
- **Pages**: Home (hero + inline scanner), Scan (new scan form with progress),
  Dashboard (immediate scan results), History (paged table), Report (full
  stored report incl. AI card, threat-intel card and export toolbar).
- **Client-side validation** (`src/utils/formatters.js` `validateTarget`):
  rejects spaces, invalid characters, and malformed hostnames before a request
  is made; the backend independently re-validates.
- **Rendering**: feature-grouped components — `dashboard/` (TrustScore,
  RiskSummary, ModuleGrid, FindingsList, RecommendationPanel, OverallAssessment,
  ScanTimeline), `report/` (AiExplanationCard, WhyRiskPanel, ExportToolbar),
  `threatintel/` (ThreatIntelCard), `scan/` (ScanInput, ScanProgress,
  ScanSummary), `common/` (Card, Badge, Button, Alert, Loader, StateViews),
  `layout/` (Navbar, Sidebar, Footer, PageLayout).
- Provider slugs are displayed via a mapping (`formatters.js`): e.g.
  `google-safe-browsing` → “Google Safe Browsing”; unknown slugs render
  title-cased, never raw.

There is no SPA state for scan history — the History/Report pages always fetch
from the backend.

## 3. Backend Architecture

Location: `backend/app/` — FastAPI application (`main.py`).

| Layer | Directory | Responsibility |
| --- | --- | --- |
| HTTP | `api/routes/` | Thin endpoint definitions; no business logic |
| Orchestration | `services/` | `scan_service`, `scan_manager`, `history_service`, `reporting_service`, `ai_explanation_service` |
| Modules | `modules/<name>/` | One scanner family per folder (`scanner.py`, `service.py`, `rules.py`, …) |
| Risk Engine | `risk_engine/` | Deterministic scoring (`engine.py`, `scorer.py`, `weights.py`, `verdict.py`) |
| Contracts | `schemas/` | Pydantic models — the canonical API contracts |
| Database | `database/` | SQLAlchemy engine, session, `Scan` model |
| Config | `core/` | `config.py` (env-driven), `scan_ids.py`, `logging`, `exceptions` |
| Utils | `utils/` | URL normalization/validation, outbound-network safety, time/helpers |

`main.py` calls `init_db()` at import (idempotent table creation, never drops
data), configures CORS from `CYBERSHIELD_CORS_ORIGINS`, and registers all
routers. The complete route table:

| Method | Path | Purpose |
| --- | --- | --- |
| GET | `/` | Root banner (not in OpenAPI schema) |
| GET | `/health` | Health check |
| GET | `/scan/{target}` | Full scan (target URL-encoded, up to 2048 chars) |
| POST | `/scan` | Full scan, body `{"target": "…"}` |
| GET | `/url-analysis/{url:path}` | URL analysis module only |
| GET | `/whois/{domain}` | WHOIS module only |
| GET | `/dns/{domain}` | DNS module only |
| GET | `/ssl/{domain}` | SSL/TLS module only |
| GET | `/headers/{domain}` | Security headers module only |
| GET | `/ports/{host:path}` | Port exposure check (standalone, not in pipeline) |
| GET | `/reputation/{domain}` | Reputation module only |
| GET | `/typosquatting/{domain}` | Typosquatting module only |
| GET | `/brand-detection/{domain}` | Brand detection module only |
| GET | `/threatintel/{domain}` | Threat intelligence module only |
| GET | `/history?limit=&offset=` | Paginated scan list envelope |
| GET | `/history/{scan_id}` | Full stored analysis |
| GET | `/reports/{scan_id}/{fmt}` | Export `json` / `csv` / `pdf` from the stored snapshot |

Note: a `ports` module exists and is exposed standalone at `/ports/{host}`, but
it is **not** part of the scan pipeline (it is absent from the module registry,
see §5).

## 4. `/scan` Request Flow

Both `GET /scan/{target}` and `POST /scan` delegate to
`app.services.scan_service.run_scan(target)` (window is identical). The GET path
is capped at `MAX_TARGET_LENGTH = 2048` characters (422 otherwise).

```
run_scan(target)
 ├─ ScanManager.run(target)  →  asyncio.run(arun)
 │    ├─ scan_id = CS-YYYY-XXXXXXXXXXXX (secrets.token_hex(6), core/scan_ids.py)
 │    ├─ normalize_url()  → ensure http(s) scheme, strip whitespace
 │    ├─ extract_domain() → urlparse hostname, lowercased
 │    ├─ validate_url()   → scheme ∈ {http, https} and netloc present
 │    ├─ Stage 0 (sequential): url_analysis   (full-URL scanner)
 │    ├─ Stage 1 (concurrent, only if target is valid):
 │    │    asyncio.gather(*[asyncio.to_thread(m.run, domain) …])
 │    │    — reputation, whois, dns, ssl, headers, typosquatting,
 │    │      brand_detection, threatintel, blacklist, phishing
 │    ├─ engine(results) → AnalysisResponse (score, confidence, verdict,
 │    │    severity summary, modules in registry order, ranked findings)
 │    └─ stamp scan_id, target, normalized_url, domain, started/completed_at
 ├─ AIExplanationService().generate(analysis)   (optional; §15)
 └─ save_scan(analysis)  (best-effort; a failure is logged and ignored)
```

- Each module runs inside `asyncio.to_thread` because module scanners perform
  blocking network I/O; the domain stage therefore executes concurrently.
- `results` preserves registry order into the response, so output is stable
  regardless of concurrent completion order.
- If the target is invalid, domain scanners never run: the result carries the
  URL-analysis `is_valid: false` signal with confidence 0, so an invalid or
  garbage input can never acquire a confident malicious classification.

## 5. Analysis Module Architecture

The scanner contract (`app/modules/base.py`):

- `BaseModule` exposes `name`, `description`, `target_kind` and `run(target)`
  returning a canonical `ModuleResult`.
- `TARGET_URL = "url"` scanners run **first, sequentially** (structural checks).
  `TARGET_DOMAIN = "domain"` scanners run **after, concurrently**.
- Modules **never call other modules**; the ScanManager is the only
  coordination layer (dependency-injected for tests).
- The pipeline roster lives in `app/modules/registry.py` (`MODULE_REGISTRY`):
  adding a scanner to the registry is the only change needed to include it in
  every scan — the ScanManager and Risk Engine are untouched.

Registered pipeline (in order) and their module weights:

| # | Module | target_kind | Weight |
| --- | --- | --- | --- |
| 0 | `url_analysis` | URL | 20 |
| 1 | `reputation` | domain | 15 |
| 2 | `whois` | domain | 5 |
| 3 | `dns` | domain | 10 |
| 4 | `ssl` | domain | 10 |
| 5 | `headers` | domain | 5 |
| 6 | `typosquatting` | domain | 10 |
| 7 | `brand_detection` | domain | 10 |
| 8 | `threatintel` | domain | 15 |
| 9 | `blacklist` | domain | 10 |
| 10 | `phishing` | domain | 10 |

A module that raises is caught by the ScanManager and replaced with a
`ModuleResult(status="error", score=0, confidence=0, details={"error": …})` —
one broken scanner never aborts the scan.

## 6. Standardized Module Output Contract

Every module returns `ModuleResult` (`app/schemas/module_result.py`):

```jsonc
{
  "module": "dns",
  "status": "ok | warning | critical | error",
  "score": 0–100,
  "confidence": 0–100,
  "findings": [ /* Finding */ ],
  "details": { /* module-specific evidence, arbitrary JSON */ }
}
```

- `status` derives from `score_to_status(score)`: `ok` ≥ 90, `warning` ≥ 70,
  `critical` < 70; `error` is only assigned by the ScanManager's safety net.
- Each `Finding` (`app/schemas/finding.py`) carries `title`, `severity`
  (`critical|high|medium|low|info`), `description`, `explanation` (why it
  matters), `recommendation`, `evidence` (concrete data) and `confidence`.
- Module-specific evidence stays in `details`; the structured, explainable
  findings live in `findings`. Modules are not allowed to return ad-hoc shapes.

## 7. Risk Engine

`app/risk_engine/` is the deterministic aggregation layer:

- **`engine.py`** — facade: collects every `ModuleResult`, calls the scorer,
  sorts findings by severity (`critical → … → info`), builds the `severity`
  summary counts, and produces the `AnalysisResponse` (modules keep registry
  order). It also retains a legacy compatibility wrapper used by no current
  route.
- **`scorer.py`** — the math:
  - `effective score = round(module.score × module.confidence / 100)`
  - weights come from `weights.py`; a module with `status == "error"` has its
    weight multiplied by `ERROR_CONFIDENCE_PENALTY = 0.5`.
  - weights are **re-normalized over modules that contributed**, so a partially
    successful scan still yields a meaningful 0–100 score.
  - `compute_confidence` is the same weighted aggregation over module
    confidences with the same error discount.
- **`weights.py`** — the weight table above plus `ERROR_CONFIDENCE_PENALTY`.
- **`verdict.py`** — re-exports the shared `Verdict` enum and threshold
  constants (canonical mapping lives in `app/schemas/verdict.py`).

## 8. Trust Score

The Trust Score is a **weighted average of module scores scaled by their
confidence**, rounded half-up and clamped to 0–100, with the weight table in
§5. Deterministic by construction:

```
trust_score = Σ(weight_i × effective_score_i) / Σ(weight_i)
effective_score_i = round(module_score_i × confidence_i / 100)
```

Design consequences:

- A low-confidence module result automatically drags less weight into the
  score.
- An errored module contributes at half weight (never full, never zero-noise).
- Because per-module penalties originate in the module scanners themselves
  (`rules.py` per module), every point in the score is traceable to evidence.

In practice: the reference scan of `https://example.com` produced module
scores the engine aggregated into `trust_score: 83`.

## 9. Verdict and Confidence

Verdict boundaries (`app/schemas/verdict.py`):

| Trust Score | Verdict |
| --- | --- |
| 90–100 | Trusted |
| 75–89 | Low Risk |
| 60–74 | Moderate Risk |
| 45–59 | Suspicious |
| 25–44 | High Risk |
| 0–24 | Critical |

`confidence` (0–100) is the confidence-weighted aggregate described in §7 —
it expresses how much the contributing modules actually asserted, so a scan
whose evidence base degraded (errored modules, unavailable providers) reports
lower confidence rather than inventing certainty.

## 10. Findings and Recommendations

- The engine flattens every module's `findings` and sorts them by severity
  (`critical` highest). The top-level `summary` counts findings per severity.
- The frontend renders them in two panels: **Findings** (each with title,
  severity badge, description, explanation, evidence, recommendation) and
  **Recommendations** (priority actions) on both Dashboard and Report pages.
- Findings are produced by module rule sets (e.g. missing `Content-Security-
  Policy` → `high` medium-confidence finding with a remediation string).

## 11. Threat Intelligence Architecture

The `threatintel` module (`app/modules/threatintel/`) has two layers:

1. **Local heuristics — always run** (`scanner.py`): phishing keyword rules,
   malware host-pattern rules, and a static/local blacklist feed. Penalties:
   phishing 30, malware 40, feed-flagged 50 (rules in `rules.py`).
2. **External providers — additive, only when configured and enabled**
   (master switch `CYBERSHIELD_THREAT_PROVIDER_ENABLED`, default `true`).
   Each adapter returns a normalized `ThreatIntelSignals`; the scanner
   applies a confidence-scaled penalty (`base × confidence/100`, round-
   half-up), caps the sum at `PROVIDER_PENALTY_CAP = 40`, emits a per-provider
   finding, and — when at least one provider answered — one aggregated
   correlation finding (`details.threat_intel_correlation`).

Normalized contract (`app/schemas/threat_intel.py`): `provider`, `status`
(`available`/`unavailable`), `reason` (typed: timeout, rate_limited,
unauthorized, bad_response, no_analysis, …), `malicious`/`suspicious` flags,
`detections`, `categories`, `confidence` (0–100), `evidence` (list), timestamp.

**Invariant**: an `unavailable` signal is a missing data point, never a
verdict. It contributes no penalty and is explicitly never counted as a
dissenting vote in correlation.

## 12. Google Safe Browsing Adapter

`app/modules/threatintel/adapters/google_safe_browsing.py`

- Endpoint: `POST https://safebrowsing.googleapis.com/v4/threatMatches:list`
  (`key` query param; timeout default 5 s).
- Requests a fixed set of `threatTypes` (MALWARE, SOCIAL_ENGINEERING,
  UNWANTED_SOFTWARE, POTENTIALLY_HARMFUL_APPLICATION, MALICIOUS_BINARY) for the
  normalized URL.
- Response normalization: raw `threatType` labels map through
  `KNOWN_THREAT_TYPES` (5 recognized categories; unknown labels fold into
  `unknown`). `malware`/`malicious-download` → `malicious`; `social-
  engineering`/`unwanted-software`/`exploit` (via suspicious set) →
  `suspicious`.
- **Confidence**: implied default `90` when a threat is reported, `10`
  otherwise (documented as provider-implied, not evidence-derived).
- Failure mapping: 429 → `rate_limited`; 401/403 → `unauthorized`; 400 →
  `invalid_target`; 5xx → `server_error`; timeout/network → `timeout`/`network`;
  malformed JSON → `bad_response`. Never a malicious verdict.
- Security: the key travels only in the query string and is never logged (the
  adapter logs exception *class names*, not request details).

## 13. VirusTotal Adapter

`app/modules/threatintel/adapters/virustotal.py`

- Endpoint: `GET https://www.virustotal.com/api/v3/urls/{url_id}` where
  `url_id` is base64url(normalized_url) without padding; key in the
  `x-apikey` header; timeout default 8 s. One request per scan, **no retries**
  (free tier ≈ 4 req/min, 500 req/day).
- **404 mapping**: a `ResourceNotFoundException` means VirusTotal has no record
  — that is `unavailable` with reason `no_analysis`, *never* a clean verdict.
- Confidence is **evidence-derived**: `min(100, 30 + 15·malicious + 10·
  suspicious)` engine counts, 0 when nothing flagged (the provider supplies no
  confidence itself).
- Categories are inferred deterministically from flagged engine verdict text
  via a keyword table (phish/spam → phishing; trojan/ransomware/stealer →
  malware; adware/PUA → unwanted-software;…) — unmatched text never invents a
  category.
- Evidence strings are bounded (160 chars per engine row) and composed from
  sanitized fields only (engine tally, engine: verdict, reputation score, last
  analysis date).

## 14. Provider Correlation

`app/modules/threatintel/correlation.py` + `schemas/threat_correlation.py`

The correlation engine deliberately **never imports adapters and never switches
on provider names**; it only reads normalized `ThreatIntelSignals`:

- **Agreement**: `consistent` (all available providers agree), `partial`
  (differ without hard conflict), `conflict` (malicious AND clean verdicts
  coexist), `none` (no provider answered). Disagreement on `suspicious` vs
  `clean` counts as partial, not conflict.
- **Consensus**: `malicious` / `suspicious` / `clean` / `conflict` /
  `unavailable`.
- **Confidence aggregation** (documented formula, deterministic):
  `base = max(confidence of malicious-signal providers)` + `AGREEMENT_BONUS ×
  (malicious_count − 1)` — multiplied by `CONFLICT_MULTIPLIER` (0.85 default)
  when providers conflict — rounded half-up, clamped 0–100. A signal carrying
  zero confidence keeps the aggregate at zero (never guessed). The suspicious
  confidence aggregates identically without the conflict multiplier.
- Tuning values arrive from env (`THREAT_INTEL_AGREEMENT_BONUS`,
  `THREAT_INTEL_CONFLICT_MULTIPLIER`) and are clamped defensively.
- Aggregate findings supplement (never replace) per-provider findings, and
  preserve conflict as a first-class outcome (“the disagreement is preserved
  instead of averaged away”, mirrored in the UI).
- Duplicate provider signals collapse (first occurrence wins); categories and
  evidence are deduplicated and sorted for determinism.

## 15. AI Explanation Layer

`app/services/ai_explanation_service.py`,
`app/modules/ai_explanation/`, `app/schemas/ai_explanation.py`

- **Disabled by default** (`AI_ENABLED` defaults to `false`). Requires an
  OpenAI-compatible chat-completions endpoint (`AI_BASE_URL`, default
  `https://api.openai.com/v1`), `AI_MODEL`, `AI_API_KEY` (env-only),
  `AI_TIMEOUT_SECONDS` (30), `AI_MAX_TOKENS` (800).
- The provider (`providers/openai_compatible.py`) posts a system prompt +
  evidence JSON, requests `response_format: {"type": "json_object"}`, and is
  implemented over `httpx` (no SDK). One attempt, no retries.
- **Evidence package is an allowlist** (`evidence.py`): only target, normalized
  URL, domain, severity counts, per-module `{module,status,score,confidence}`
  (no raw `details`), the first 20 findings (bounded fields, 240 chars each),
  and the normalized threat-intel correlation view. **The Trust Score,
  confidence, verdict and all credentials are deliberately excluded** — the
  model is score-blind.
- **Strict output validation**: the response must parse as JSON and satisfy
  `AIExplanation` (summary ≤ 800 chars, `why_risky` ≤ 2000, 1–12 risk factors,
  technical explanation ≤ 2500, 1–12 recommended actions, `generated_by`
  default `ai-external`). Any violation discards the whole explanation.
- **Failure isolation**: disabled, unconfigured, timeout, malformed output or
  schema violation all yield `ai_explanation: null` with the deterministic
  result byte-identical (asserted by tests).
- The frontend renders `AiExplanationCard` **only when the payload exists**, and
  its footer states the text does not change the assessment.

## 16. Persistence / History

`app/database/` (SQLAlchemy 2.x, SQLite by default; a PostgreSQL URL via
`CYBERSHIELD_DATABASE_URL` uses the same models).

- Single table `scans` (`models.py`): integer PK; `scan_id` unique+indexed;
  scalar columns mirroring top-level fields (`target_url`, `normalized_url`,
  `domain`, `trust_score`, `confidence`, `verdict`, `summary_json`, timestamps)
  so list queries stay cheap; `analysis_json` stores the **full serialized
  `AnalysisResponse` snapshot** so reports reconstruct exactly.
- `history_service.py` owns all SQL: `save_scan` (insert; `expire_on_commit=
  false`), `get_scan` (returns `AnalysisResponse` or raises a typed
  `StoredAnalysisError` on malformed snapshots), `list_scans(limit, offset)`
  newest-first with total count.
- `save_scan` is invoked **after** the response is fully built; any exception
  is logged and swallowed (`logger.exception`), so persistence failure cannot
  alter the response.
- Storage is initialized idempotently at import (`init_db()` → `create_all`).
- On Docker, the SQLite file lives on the host at `./data/cybershield.db`
  through a bind mount and survives container restarts (verified).

## 17. Reporting / Export Architecture

`app/api/routes/reports.py` + `app/services/reporting_service.py` +
`app/modules/reporting/{json,csv,pdf}.py`

- Route guards first: scan IDs are validated against `^[A-Za-z0-9-]{1,64}$`
  (404 otherwise) and the format must be in `MEDIA_TYPES` (`json`, `csv`,
  `pdf`) — 422 otherwise. Never rescanning: the report is rendered from the
  **stored snapshot** loaded by `history_service.get_scan`.
- `reporting_service.generate_report` is the format coordinator; the download
  filename is built **only from the validated scan id**
  (`cybershield-<scan_id>.<ext>`), never from user input.
- JSON: full serialized analysis. CSV: flattened findings with formula-
  injection guards. PDF: reportlab-rendered document.
- All exporters write bounded, validated data; responses set
  `X-Content-Type-Options: nosniff` and `Cache-Control: no-store`.
- Frontend ExportToolbar requests blobs and triggers client-side downloads.

## 18. Docker Deployment Architecture

`docker-compose.yml` + `backend/Dockerfile` + `frontend/Dockerfile`

- **backend** (`python:3.12-slim`): copies `requirements.txt`, `pip install`,
  copies `app/`, runs `uvicorn app.main:app --host 0.0.0.0 --port 8000`.
  Exposed `8000:8000`.
- **frontend** (multi-stage: `node:20-alpine` build → `nginx:alpine` serve):
  `VITE_API_BASE_URL` is passed as a build arg (default
  `http://localhost:8000`), `npm run build`, static assets served by nginx on
  `80:80`. The build stage uses `npm install --no-audit --no-fund` rather than
  `npm ci` because npm 10.8.x on Node 20 skips rolldown's platform-native
  optional dependency in `npm ci` (npm/cli#4828), which broke the build.
- **Persistence**: bind mount `./data:/app/data`; the backend is configured
  with `CYBERSHIELD_DATABASE_URL=sqlite:////app/data/cybershield.db`, so Docker
  runs persist across rebuilds/restarts (verified end-to-end).
- **Secrets/config**: `env_file` → `./backend/.env` with `required: false`;
  env vars travel only through the composition (e.g.
  `CYBERSHIELD_CORS_ORIGINS=http://localhost`). No secret values are
  hard-coded anywhere in the Docker configuration.
- Runtime flow: `docker compose up --build` → frontend at `http://localhost`,
  API at `http://localhost:8000` with CORS configured for `http://localhost`.

## 19. Error / Failure Handling

| Failure class | Behavior |
| --- | --- |
| Invalid target (bad scheme, no host, whitespace) | URL validation fails → `is_valid: false`, confidence 0, domain scanners skipped; no confidence can be built |
| Target too long (> 2048) | 422 from the scan route |
| Module raises | Replaced with `ModuleResult(status="error", score=0, confidence=0)`; pipeline continues; slight weight discount (×0.5) |
| WHOIS/registry unavailable | Informational `info` finding, zero penalty — never malicious |
| External provider fails/timeout/rate-limit/404 | `unavailable` signal with typed reason; zero penalty; correlation ignores it |
| Provider conflict | Preserved as `conflict` consensus; confidence dampened by multiplier |
| Storage write fails | Logged and swallowed; response unchanged |
| AI disabled/unconfigured/fails/validation mismatch | `ai_explanation: null`; response otherwise unchanged |
| Unknown scan id / bad format on report export | 404 / 422 before any generation |
| Private/loopback/reserved target hosts | Refused by `validate_public_host` before connection (headers, ports modules) |

Logging is namespaced per subsystem (`cybershield.*`); provider/AI failures log
exception **classes**, never payloads or keys.

## 20. Security Boundaries

- **Secrets via environment only.** API keys (`GOOGLE_SAFE_BROWSING_API_KEY`,
  `VIRUS_TOTAL_API_KEY`, `AI_API_KEY`) come from the environment, are never
  hard-coded, persisted or logged; compose passes them via `env_file`.
- **SSRF guards** (`app/utils/networking.py`). Modules that contact a
  user-supplied host (headers, ports) call `validate_public_host`: hostnames
  like `localhost`/`.local` are refused outright; DNS results are checked
  against `is_private`, `is_loopback`, `is_link_local`, `is_reserved`,
  `is_multicast`, `is_unspecified`, plus the CGNAT range `100.64.0.0/10`
  (RFC 6598). Any non-public record → refused (defense in depth).
- **CORS allowlist.** `CYBERSHIELD_CORS_ORIGINS` (default: local Vite dev
  origins); production/Docker sets `http://localhost`. Never `*`.
- **Input validation.** URL shape, scan-target length, module-level rules; the
  frontend additionally pre-validates.
- **Output/response hardening.** Report scan IDs regex-validated before use in
  filenames; `X-Content-Type-Options: nosniff`; `Cache-Control: no-store` on
  exports; AI output schema-validated; provider signals normalized with
  bounded fields; CSV exporters guard against formula injection.
- **No fabricated guarantees.** An unavailable provider or WHOIS failure is
  never presented as cleanliness; low-confidence flags never read as critical
  (`_severity_for` ladder).
- **Deployment scope.** Single-user, no authentication — CyberShield is a
  local/portfolio deployment, not a multi-tenant SaaS.