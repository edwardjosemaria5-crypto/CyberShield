# CyberShield

CyberShield is a full-stack website security assessment platform. Submit a domain or URL and it runs a battery of detection modules — DNS, WHOIS, SSL/TLS, security headers, reputation, phishing, typosquatting, threat intelligence and more — then aggregates the evidence into an explainable Trust Score, verdict and findings with recommendations.

## Overview

### The problem

Most web users cannot distinguish a legitimate site from a phishing clone, a typosquatting domain, or a recently registered domain set up for abuse. Checking a URL manually means consulting WHOIS registries, certificate transparency, DNS records, blacklists and threat-intelligence feeds separately — and then deciding how much any single signal should matter.

### What CyberShield does

CyberShield replaces that manual process with a single scan that:

- inspects the **structure of the URL** (scheme, host, length, punycode, suspicious keywords),
- interrogates the domain's **DNS, WHOIS, SSL/TLS and HTTP security headers**,
- checks **reputation, blacklists, phishing heuristics, typosquatting and brand impersonation**,
- correlates **external threat-intelligence providers** (Google Safe Browsing, VirusTotal) when API keys are configured,
- feeds every module result into a deterministic **Risk Engine** that produces a 0–100 **Trust Score**, a **verdict** and a **confidence** level,
- attaches an **optional AI-generated explanation** of *why* the result was reached — the AI explains evidence, it never decides the score.

The output is an explainable assessment: every finding carries a severity, a plain-language description, and a recommendation.

> CyberShield does not claim to be a malware-analysis tool. It is a defensive *assessment* platform: it collects evidence, measures risk signals, and explains the reasoning. Unavailable data (e.g. a failed WHOIS lookup) is never treated as evidence of maliciousness.

## Key Features

| Area | What it does |
| --- | --- |
| URL analysis | Validates the target, normalizes scheme/host, flags IP literals, punycode, length and suspicious keywords |
| DNS intelligence | Resolution, MX/SPF/DMARC posture, DNSSEC, mail configuration |
| HTTP security headers | Grades presence of CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy and CAA |
| WHOIS intelligence | Registrar, registration age, expiry risk, name servers, DNSSEC status |
| SSL/TLS analysis | Certificate validity, chain, TLS version and cipher posture |
| Port intelligence | Public port exposure checks |
| Reputation | Domain age and heuristic reputation scoring |
| Blacklist analysis | Membership against local/static blacklist feeds |
| Phishing detection | Heuristic phishing-risk analysis of the hostname |
| Typosquatting detection | Brand-similarity analysis against known brand names |
| Brand detection | Keyword-combination and impersonation signals |
| Threat intelligence | Local heuristics plus external provider lookups |
| Google Safe Browsing | Threat-match lookups via the v4 API (when configured) |
| VirusTotal | v3 URL analysis lookups (when configured) |
| Multi-provider correlation | Provider-independent agreement/conflict reconciliation |
| Risk Engine | Deterministic weighted aggregation of module scores |
| Trust Score | 0–100 score with confidence and verdict mapping |
| Explainable findings | Severity-ranked findings, each with description + recommendation |
| AI explanations | Optional, score-blind plain-language summary of the evidence |
| Scan history & persistence | Every scan stored; retrievable by scan ID |
| Reporting | JSON, CSV and PDF export of completed reports |
| Frontend | React dashboard, scan workflow, report page and history views |

## How It Works

```
User / UI
   │   POST/GET /scan/{target}
   ▼
ScanManager ── pipeline orchestrator
   ├── Stage 0 (sequential): URL analysis (structural checks)
   ├── Stage 1 (concurrent): DNS, WHOIS, SSL, headers, reputation, blacklist,
   │                        phishing, typosquatting, brand detection, threat intel
   ▼
Standardized ModuleResult per module (score + confidence + findings)
   ▼
Threat Intelligence ── provider adapters → correlation (only if configured)
   ▼
Risk Engine ── weighted trust score, aggregated confidence, verdict
   ▼
AnalysisResponse ── trust score, verdict, confidence, modules, findings, summary
   ▼
AI Explanation (optional) ── adds score-blind prose, never changes results
   ▼
Report / UI ── dashboard, findings, recommendations, history, exports
```

Key properties of the pipeline:

- **Targets are validated up front.** An invalid or garbage URL is rejected (`is_valid: false`, `confidence: 0`). Domain scanners never run against it, so it cannot acquire a confident malicious classification.
- **Modules are isolated.** A failing module is replaced by an error result; it cannot abort or poison the rest of the scan.
- **Scoring is deterministic.** The Risk Engine owns the score, verdict and confidence. The AI layer is a presentation add-on.
- **Persistence is best-effort.** A storage failure never alters the response the user receives.

## Risk Engine

The Risk Engine is the deterministic aggregation layer (`backend/app/risk_engine/`).

- Every module produces a **ModuleResult**: a 0–100 module score, a confidence 0–100, status, and findings.
- Module scores are aggregated with **configured weights** (e.g. URL analysis 20, reputation 15, threat intelligence 15, DNS/SSL 10 each — full table in `backend/app/risk_engine/weights.py`). Weights are re-normalized over the modules that actually produced results, so a partially successful scan still yields a meaningful score.
- A module that **errors out** contributes at reduced effective weight (`ERROR_CONFIDENCE_PENALTY = 0.5`), so a broken module cannot drag or inflate the result.
- **Confidence** is the weighted average of module confidences, with the same error discounting.

Verdict boundaries (`backend/app/schemas/verdict.py`):

| Trust Score | Verdict |
| --- | --- |
| 90–100 | Trusted |
| 75–89 | Low Risk |
| 60–74 | Moderate Risk |
| 45–59 | Suspicious |
| 25–44 | High Risk |
| 0–24 | Critical |

Design principle: a **failure to obtain evidence is never evidence of maliciousness**. For example, an unavailable WHOIS lookup yields an informational finding and a zero penalty (score stays 100); it never becomes a security finding.

## Threat Intelligence

CyberShield ships local heuristics (phishing keywords, malware patterns, static blacklist feeds) that always run, plus an adapter layer for **external providers**:

- **Google Safe Browsing** (v4 `threatMatches`) — used when `GOOGLE_SAFE_BROWSING_API_KEY` is set.
- **VirusTotal** (v3 URL analysis) — used when `VIRUS_TOTAL_API_KEY` is set. Free-tier limits (~4 req/min, ~500 req/day) apply; CyberShield issues one request per scan and never retries.

Behavioral rules enforced by tests:

- **A failed provider lookup is a missing data point, never a verdict.** Every failure maps to an `unavailable` signal with a reason (timeout, rate-limit, unauthorized, bad response, no analysis…).
- **Unavailable signals add no penalty.** Only *available* signals carrying `malicious`/`suspicious` reduce the module score, and provider penalties are capped.
- **Multi-provider correlation** reconciles providers without knowing provider names: agreement is `consistent` / `partial` / `conflict` / `none`, computed only among *available* providers — an unavailable provider never counts as a dissenting vote.
- **Aggregated confidence is not an average.** It starts from the strongest flagging signal, adds a bonus per extra agreeing provider, and applies a multiplier when providers conflict; it is clamped to 0–100 and never guessed when providers report zero confidence (provider-derived confidence formulas are documented in `backend/README.md`).

## AI Explanation

The AI layer (`backend/app/modules/ai_explanation/`) is **optional and strictly presentational**:

- It is **disabled by default** (`AI_ENABLED=false`) and requires an OpenAI-compatible chat-completions endpoint plus an environment-only API key.
- It explains the deterministic result in plain language. It **never calculates or influences** the Trust Score, verdict, confidence or findings.
- The evidence package sent to the model is **score-blind**: it deliberately excludes the Trust Score, confidence and verdict, plus any credentials or raw module details.
- **AI failure cannot break a scan.** Disabled, unconfigured, timed out, malformed output or schema violation — any of these degrades gracefully to `ai_explanation: null` with an otherwise unchanged result.
- Output is schema-validated (bounded fields, 1–12 explanation factors/actions) before it is stored or rendered.

## Results / Report

A completed scan exposes:

- **Target** (raw input, normalized URL, extracted domain, scan ID)
- **Trust Score** — 0–100 gauge, tinted by score
- **Verdict** — one of the six verdict labels
- **Confidence** — 0–100%, rendered explicitly
- **Module analysis** — a card per module with status, score, confidence and expandable details
- **Findings** — severity-ranked (critical → high → medium → low → info), each with description and recommendation
- **Threat intelligence** — provider cards showing availability and verdicts
- **AI explanation** — optional prose summary of why the result was reached
- **Overall assessment** — generated narrative tying score, confidence and findings together
- **History** — every scan persisted and retrievable
- **Exports** — JSON, CSV and PDF of the stored report (CSV output guards against formula injection)

The frontend shows this through the **Dashboard** (immediate scan results), the **Report page** (saved scans by ID), and **History** (paged list with total counts).

## Tech Stack

| Layer | Technology |
| --- | --- |
| Backend | Python · FastAPI · Uvicorn · Pydantic |
| Scanning | python-whois · dnspython · cryptography · httpx · requests |
| Reporting | reportlab (PDF) · stdlib csv/json exporters |
| Persistence | SQLAlchemy · SQLite (PostgreSQL-compatible URL format) |
| Frontend | React 19 · Vite 8 · React Router 7 · axios |
| Testing | pytest · pytest-asyncio · pytest-cov (backend) · ESLint (frontend) |
| External providers | Google Safe Browsing v4 · VirusTotal v3 (optional) · any OpenAI-compatible chat endpoint (optional AI) |
| Deployment | Docker Compose (backend + frontend images) |

## Project Structure

```
CyberShield/
├── backend/
│   ├── app/
│   │   ├── api/routes/        # FastAPI endpoint definitions
│   │   ├── core/              # config, logging, scan ID generation, exceptions
│   │   ├── database/          # SQLAlchemy models and connection
│   │   ├── modules/           # one folder per analysis module (scanner + rules + service)
│   │   │   ├── url_analysis/  # dns/ whois/ ssl/ headers/ ports/ reputation/
│   │   │   ├── blacklist/     # phishing/ typosquatting/ brand_detection/
│   │   │   ├── threatintel/   # provider adapters + correlation
│   │   │   └── ai_explanation/# optional explanation layer
│   │   ├── risk_engine/       # weighted scoring, confidence, verdicts
│   │   ├── schemas/           # canonical API contracts (Pydantic)
│   │   └── services/          # scan orchestration, history, reporting
│   ├── tests/                 # 278 pytest cases
│   └── .env.example           # environment template (no secrets)
├── frontend/
│   └── src/
│       ├── pages/             # Home, Scan, Dashboard, History, Report, Settings
│       ├── components/        # dashboard/ scan/ report/ threatintel/ common/ layout
│       ├── context/ hooks/    # scan state and data access
│       └── services/          # API client (axios)
├── docker-compose.yml         # backend :8000 + frontend :80
├── docs/                      # supplementary documentation
└── README.md
```

## Installation

### 1. Prerequisites

- Python 3.11+ (the project targets the 3.x line; developed on 3.14)
- Node.js 20+ and npm
- (Optional) Docker with Docker Compose for containerized runs

### 2. Backend environment setup

From the repository root:

```sh
python -m venv .venv
```

Windows:

```sh
.venv\Scripts\python.exe -m pip install -r backend\requirements.txt
```

macOS / Linux:

```sh
.venv/bin/python -m pip install -r backend/requirements.txt
```

### 3. Environment variables

```sh
copy backend\.env.example backend\.env     # Windows
cp backend/.env.example backend/.env       # macOS / Linux
```

No variables are *required* to run a scan. Without provider keys, CyberShield runs on local heuristics and static feeds; without `AI_ENABLED=true` and a key, no AI explanation is produced.

### 4. Frontend dependencies

```sh
cd frontend
npm install
```

### 5. Start the backend

```sh
cd backend
..\.venv\Scripts\python.exe -m uvicorn app.main:app --reload --port 8000
```

The API is then available at `http://localhost:8000` (interactive docs at `/docs` by virtue of FastAPI).

### 6. Start the frontend

In a second terminal:

```sh
cd frontend
npm run dev
```

Open `http://localhost:5173`. The default CORS allowlist already matches this dev origin.

### 7. Docker (alternative)

```sh
docker compose up --build
```

Then open `http://localhost`. SQLite data is persisted on the host in `./data/cybershield.db`. Configure optional provider/AI keys by copying `backend/.env.example` to `backend/.env` before starting.

## Environment Variables

All configuration is read from the environment (see `backend/.env.example` and `backend/app/core/config.py`). Secrets are never hard-coded, logged or stored.

| Variable | Default | Required | Purpose |
| --- | --- | --- | --- |
| `CYBERSHIELD_DATABASE_URL` | `sqlite:///cybershield.db` | no | SQLAlchemy database URL |
| `CYBERSHIELD_CORS_ORIGINS` | local Vite dev origins | no | Comma-separated allowed browser origins (never `*` in production) |
| `GOOGLE_SAFE_BROWSING_API_KEY` | *(empty)* | no | Enables the Safe Browsing provider when set |
| `GOOGLE_SAFE_BROWSING_TIMEOUT_SECONDS` | `5.0` | no | Provider request timeout |
| `VIRUS_TOTAL_API_KEY` | *(empty)* | no | Enables the VirusTotal provider when set |
| `VIRUS_TOTAL_TIMEOUT_SECONDS` | `8.0` | no | Provider request timeout |
| `CYBERSHIELD_THREAT_PROVIDER_ENABLED` | `true` | no | Master switch for all external provider lookups |
| `THREAT_INTEL_AGREEMENT_BONUS` | `10` | no | Confidence points per extra agreeing provider |
| `THREAT_INTEL_CONFLICT_MULTIPLIER` | `0.85` | no | Confidence dampener for conflicting provider verdicts |
| `AI_ENABLED` | `false` | no | Master switch for the explanation layer |
| `AI_PROVIDER` | `openai-compatible` | no | Provider name (unknown names resolve to disabled) |
| `AI_MODEL` | `gpt-4o-mini` | no | Model id sent to the endpoint |
| `AI_API_KEY` | *(empty)* | no | Key for the AI endpoint (env-only) |
| `AI_BASE_URL` | `https://api.openai.com/v1` | no | OpenAI-compatible base URL |
| `AI_TIMEOUT_SECONDS` | `30.0` | no | Per-request AI timeout |
| `AI_MAX_TOKENS` | `800` | no | Output token cap |

## Usage

1. Open the frontend at `http://localhost:5173`.
2. Enter a valid domain or URL, e.g. `https://example.com`.
3. Start the scan — the pipeline runs the structural check first, then the domain modules concurrently.
4. Review the **Trust Score** gauge and **verdict/confidence** on the dashboard.
5. Inspect each **module card** (status, score, expandable findings).
6. Review **threat-intelligence** provider results (unavailable providers are shown as such).
7. If AI is enabled, read the **explanation** of why the result was reached.
8. Review **findings and recommendations**, sorted by severity.
9. Open **History** to see previous scans; open a **Report** from history.
10. **Export** the report as JSON, CSV or PDF.

Command-line equivalent (any scanner needs only the single scan endpoint):

```sh
curl "http://localhost:8000/scan/https%3A%2F%2Fexample.com"
```

## API

Backend endpoints (routes defined in `backend/app/api/routes/`):

| Method | Path | Purpose |
| --- | --- | --- |
| GET | `/health` | Service health check |
| GET | `/scan/{target}` | Full scan of a URL/domain (target may be a path segment) |
| POST | `/scan` | Full scan with a JSON body `{"target": "..."}` |
| GET | `/url-analysis/{url}` | URL analysis module only |
| GET | `/whois/{domain}` | WHOIS module only |
| GET | `/dns/{domain}` | DNS module only |
| GET | `/ssl/{domain}` | SSL/TLS module only |
| GET | `/headers/{domain}` | Security headers module only |
| GET | `/ports/{domain}` | Port module only |
| GET | `/reputation/{domain}` | Reputation module only |
| GET | `/typosquatting/{domain}` | Typosquatting module only |
| GET | `/brand-detection/{domain}` | Brand detection module only |
| GET | `/threatintel/{domain}` | Threat intelligence module only |
| GET | `/history?limit=&offset=` | List completed scans (paginated envelope) |
| GET | `/history/{scan_id}` | Full stored result for a scan |
| GET | `/reports/{scan_id}/{fmt}` | Export report — `fmt` in `json`, `csv`, `pdf` |

Example response overview for `GET /scan/{target}` (top-level fields):

```jsonc
{
  "scan_id": "CS-2026-XXXX…",
  "target": "https://example.com",
  "normalized_url": "https://example.com",
  "domain": "example.com",
  "trust_score": 84,
  "confidence": 89,
  "verdict": "Low Risk",
  "summary": { "critical": 0, "high": 2, "medium": 2, "low": 3, "info": 2 },
  "modules": [ /* one ModuleResult per module */ ],
  "findings": [ /* severity-ranked findings with description + recommendation */ ],
  "ai_explanation": null
}
```

Notes: scan targets are capped at 2048 characters; scan IDs are generated server-side (`CS-YYYY-…`); report exports are generated from the stored snapshot — never by rescanning.

## Testing

Status verified against the current implementation:

| Check | Result |
| --- | --- |
| Backend pytest suite | **278 passed** (`cd backend && ..\.venv\Scripts\python.exe -m pytest`) |
| Dependency health | `pip check` → no broken requirements |
| Frontend lint | `cd frontend && npm run lint` → clean |
| Frontend build | `cd frontend && npm run build` → successful |
| Real-user walkthrough | 4/4 cases passed against live API + built frontend |
| Invalid URL regression | Rejected, `is_valid: false`, confidence 0, no domain scanners run |
| WHOIS unavailable regression | Informational finding, severity `info`, zero penalty, never a malicious finding |

Tests exercise the modules, pipeline, risk engine, threat-intel adapters and correlation with injected mocks (`httpx.MockTransport`) — no network or real API keys are required. AI and provider behavior are covered by mocked tests; the deterministic result is asserted byte-identical with AI on, off, or failing.

## Security Design

- **Secrets are environment-based only.** API keys are read from the environment, never hard-coded, persisted or logged (provider/AI failures log exception *classes*, not payloads).
- **Targets are validated.** Invalid URLs are rejected with `confidence: 0`; domain scanners do not run against them.
- **Outbound SSRF guards.** Modules that contact a user-supplied host resolve it and refuse private, loopback, link-local, reserved, multicast, CGNAT (`100.64.0.0/10`) and well-known private hostnames (`localhost`, `.local`, …) before any connection.
- **Unavailable evidence is not malicious.** Provider and WHOIS failures degrade to informational/`unavailable` signals with zero penalty.
- **Failure isolation.** A failing module or a failing storage write cannot change the scan result the user receives.
- **Strict output validation.** External provider labels are normalized; AI output is schema-validated before use; report filenames derive only from validated scan IDs; responses set `X-Content-Type-Options: nosniff` and `Cache-Control: no-store`.
- **Bounded external impact.** Provider penalties are capped and external calls never retry, keeping scans user-paced.

## Known Follow-ups (not fixed in v1)

- **Frontend dependency audit finding.** `npm audit` currently reports **one
  high-severity vulnerability** in the frontend dependency tree. It is
  pre-existing, unrelated to the Docker build (which required replacing
  `npm ci` with `npm install` in `frontend/Dockerfile` to work around
  npm/cli#4828 — already resolved). No arbitrary package upgrades are being
  made; this is tracked as a security-maintenance follow-up.
- **Docker runtime** was end-to-end verified (build, startup, backend/
  frontend health, a real scan, report exports, persistence across restarts).
  Image runtime verification is not yet part of an automated CI pipeline.

## Limitations

- **External providers require keys and availability.** Without keys, threat-intel runs on local heuristics only. Google Safe Browsing and VirusTotal are subject to their own availability and rate limits (VirusTotal free tier ≈ 4 req/min, 500 req/day; one request per scan, no retries).
- **Provider confidence semantics differ.** The platform normalizes them (Safe Browsing ships implied confidence; VirusTotal's is derived from engine counts) — documented in `backend/README.md`.
- **AI is a third-party dependency when enabled.** It is optional, disabled by default, and strictly presentational, but an explanation requires a reachable OpenAI-compatible endpoint and a valid key.
- **WHOIS data availability varies by registry/domain.** A lookup may legitimately be unavailable and is treated as informational, not suspicious.
- **Heuristic scope.** Reputation, phishing, typosquatting and blacklist checks are heuristic/static feeds — they detect known signals, not all possible threats.
- **CI gaps.** The containerized runtime is verified locally, but image builds and runtime checks are not yet part of an automated CI pipeline.
- **Single-user, no authentication.** CyberShield currently runs as a local/portfolio deployment, not a multi-tenant SaaS.

## Roadmap

**Current (v1):** full pipeline, 11 modules, risk engine, threat intelligence correlation, AI explanations, history/persistence, JSON/CSV/PDF reports, frontend, 278-test backend suite, Docker composition.

**Planned (v1.1+, not yet implemented):**

- Additional threat-intelligence providers beyond Safe Browsing and VirusTotal
- Historical risk comparison and trend views
- Scheduled / recurring monitoring with alerting
- User accounts and authentication
- Deeper phishing model (e.g. ML-assisted heuristics)
- Enhanced correlation (provenance-tagged confidence)
- CI pipeline with coverage gates and containerized runtime verification

## Portfolio

CyberShield demonstrates, in one codebase:

- **Cybersecurity analysis** — multi-signal investigation of real-world risk: DNS, WHOIS, SSL/TLS, headers, reputation, phishing, typosquatting, brand impersonation, threat intel.
- **Modular architecture** — a registry-driven scanner pipeline with canonical contracts, isolated failure modes, and an engine that re-normalizes weights when modules error.
- **Risk scoring** — deterministic, weighted, confidence-aware aggregation with auditable verdict boundaries.
- **Threat-intelligence integration** — provider adapters, normalization, correlation, and the discipline of treating unavailable data as a missing data point rather than a verdict.
- **Explainability** — every finding has severity + description + recommendation; an optional score-blind AI layer explains evidence without influencing it.
- **Backend engineering** — FastAPI, Pydantic contracts, SQLAlchemy persistence, secured export endpoints.
- **Frontend engineering** — React dashboard with scan workflow, report page, history and gated exports.
- **Testing** — 278 backend tests with mocked external services, plus lint/build gates and a real-user regression walkthrough.
- **Security-conscious design** — SSRF guards, env-only secrets, input validation, failure isolation, no fabricated guarantees.

---

For deep technical documentation of the threat-intelligence and AI layers, see [`backend/README.md`](backend/README.md).