# CyberShield

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python 3.11+](https://img.shields.io/badge/Python-3.11%2B-3776AB.svg)](backend)
[![FastAPI](https://img.shields.io/badge/FastAPI-009688.svg)](backend)
[![React 19](https://img.shields.io/badge/React-19-61DAFB.svg)](frontend)
[![Docker Compose](https://img.shields.io/badge/Docker-Compose-2496ED.svg)](docker-compose.yml)
[![CI](https://img.shields.io/badge/CI-GitHub%20Actions-2088FF.svg)](.github/workflows/ci.yml)

CyberShield is a full-stack website/domain security assessment platform. Submit a domain or URL, and a pipeline of detection modules collects evidence across URL structure, DNS, WHOIS, SSL/TLS, security headers, reputation, blacklists, phishing heuristics, typosquatting and threat intelligence — plus an informational **Infrastructure context** — then aggregates it into an explainable **Trust Score**, **verdict**, **confidence** and severity-ranked **findings** with recommendations.

Every result is deterministic and evidence-based: the Risk Engine owns the score, each finding carries a severity, a plain-language description and a recommendation, and an optional AI layer explains *why* the result was reached without ever influencing it. Every completed scan is persisted, retrievable from history, and exportable as JSON, CSV or PDF.

![CyberShield dashboard — real scan result](docs/assets/dashboard-view.png)

> A genuine scan of `https://example.com` captured through the live application: Trust Score **85/100**, verdict **Low Risk**, confidence **89%**.

---

## Quick Start

The simplest verified way to run CyberShield:

```sh
docker compose up --build
# open http://localhost
```

No API keys are required. Without external provider credentials the platform runs on local heuristics and static feeds. Full local-development steps are in [Installation](#installation).

---

## The Problem

Most web users cannot tell a legitimate site from a phishing clone, a typosquatting domain, or a recently registered domain set up for abuse. Manually checking a URL means consulting WHOIS registries, DNS records, certificate details, blacklists and threat-intelligence feeds **separately** — then deciding how much any single signal should matter.

CyberShield replaces that manual process with one scan that inspects the URL's structure, interrogates the domain's DNS/WHOIS/SSL/TLS and HTTP security headers, checks reputation and heuristics, correlates optional external threat-intelligence providers, and feeds every signal into a deterministic Risk Engine that produces the Trust Score, verdict and confidence.

CyberShield is a **defensive assessment platform**, not an attack tool. It performs passive lookups only, and unavailable data (for example a failed WHOIS lookup) is never treated as evidence of maliciousness.

---

## Security Design

The strongest security engineering decisions:

| Control | Implementation |
| --- | --- |
| SSRF / outbound boundary | The scan API accepts a target for analysis; **connection-capable modules** (security headers, ports, SSL, Infrastructure) resolve the destination **once** and refuse it at connect time if it is private, loopback, link-local, reserved, multicast, CGNAT (RFC 6598) or a well-known private hostname (`backend/app/utils/networking.py`). Blocks are decided on all resolved addresses, and DNS is pinned to the validated public IP literals to close the rebinding/TOCTOU window. Defense in depth — see [Security Model](docs/security-model.md) |
| Environment-only secrets | API keys are read from the environment, never hard-coded, persisted or logged; failures log exception *classes*, not payloads (`backend/app/core/config.py`) |
| Outbound request controls | External calls never retry, provider penalties are capped, and report downloads set `nosniff` + `no-store` headers |
| Failure isolation | A failing module or storage write degrades to an error/unavailable signal and cannot change the scan result the user receives |
| Unavailable ≠ malicious | Provider and WHOIS failures become informational signals with zero penalty — missing evidence is never treated as bad evidence |
| Deterministic scoring | The Risk Engine is a pure deterministic function of module results — the AI layer never influences it |

---

## Deployment Security Boundary (Local-Only)

CyberShield's current release is **strictly local**: single-user, no
authentication, no public internet exposure.

| Component | Host publication (Compose) | Reachable from |
| --- | --- | --- |
| Frontend | `127.0.0.1:80:80` | This machine only |
| Backend | `127.0.0.1:8000:8000` | This machine only |

Inside its container the backend binds `0.0.0.0:8000`. That **internal** bind
is intentional for container networking and is safe **only** because the
container network is private and the host port is published exclusively to the
loopback interface. The security boundary is the **host publication**:

- `127.0.0.1:80:80` and `127.0.0.1:8000:8000` — loopback only. Safe as
  deployed.
- `80:80` or `8000:8000` — publishes the frontend/API beyond localhost and
  **exposes the unauthenticated API to the network**. **Prohibited** for the
  current release; changing the mappings in `docker-compose.yml` this way is a
  security regression.

HTTP without TLS is acceptable **only** because the deployment is strictly
loopback-bound. CyberShield must never be made LAN-, internet- or remotely
accessible on the current configuration: before any non-loopback deployment
the architecture must be reassessed and **HTTPS/TLS, HSTS, authentication,
authorization, rate limiting** and additional exposure controls become
required. The local HTTP setup is not suitable for public exposure.

---

## How It Works

![CyberShield v1 architecture diagram](docs/assets/cybershield-architecture.png)

A scan flows through a registry-driven pipeline:

1. **Validate** the target — invalid URLs are rejected up front and never scanned by domain modules.
2. **Scan concurrently** — 11 scored modules collect evidence: URL structure, DNS, WHOIS, SSL/TLS, HTTP security headers, reputation, blacklists, phishing heuristics, typosquatting, brand detection and threat intelligence.
3. **Add Infrastructure context** — an informational, unweighted module records hosting/location context (ASN, hosting organization, country/region) for the resolved public IPs. It is display context only: it carries no Risk Engine weight, cannot alter the Trust Score or confidence, and never creates findings.
4. **Correlate threat intelligence** — provider adapters (Google Safe Browsing, VirusTotal) reconcile only among *available* providers.
5. **Score deterministically** — the Risk Engine produces the 0–100 Trust Score, confidence and verdict from the 11 scored modules only.
6. **Explain (optional)** — a score-blind AI summary explains the result; its failure never breaks a scan.
7. **Persist and report** — every scan is stored by ID and exportable as JSON, CSV or PDF.

---

## Key Features

| Area | What it does |
| --- | --- |
| URL / domain analysis | URL structure, DNS posture, WHOIS age and registrar, SSL/TLS, HTTP security headers |
| Deterministic Risk Engine | Weighted aggregation into Trust Score, confidence and verdict (see below) |
| Explainable findings | Severity-ranked findings, each with a description and a recommendation |
| Threat intelligence | Local heuristics always run; Google Safe Browsing v4 and VirusTotal v3 adapters when keys are configured |
| Multi-provider correlation | Agreement/conflict reconciliation computed only among available providers |
| Infrastructure context | Informational hosting/location context (ASN, org, country/region) — zero weight, never affects the score |
| Optional AI explanation | Score-blind plain-language summary, disabled by default |
| History / persistence | Every scan stored and retrievable by scan ID |
| Reporting | JSON, CSV and PDF export from the stored snapshot |
| Deployment | Docker Compose (backend + frontend images), loopback-only publication |
| Automated testing | **491 backend tests + 45 frontend tests passing**; lint, production build, `pip check` clean |
| Automated CI | GitHub Actions: backend suite, frontend lint/build/tests, Docker boundary contract, committed-secret scan |

---

## Risk Engine

The Risk Engine (`backend/app/risk_engine/`) is the deterministic aggregation layer:

- Each module returns a 0–100 score, confidence and findings.
- Module scores are combined with configured weights, re-normalized over the modules that actually produced results.
- A module that errors out contributes at reduced weight (`ERROR_CONFIDENCE_PENALTY = 0.5`), so a broken module can neither drag nor inflate a result.
- Confidence is the weighted average of module confidences with the same error discounting.

| Trust Score | Verdict |
| --- | --- |
| 90–100 | Trusted |
| 75–89 | Low Risk |
| 60–74 | Moderate Risk |
| 45–59 | Suspicious |
| 25–44 | High Risk |
| 0–24 | Critical |

Design principle: a **failure to obtain evidence is never evidence of maliciousness**. An unavailable WHOIS lookup yields an informational finding and zero penalty; it never becomes a security finding.

The optional AI layer **does not control the score** — it explains an already-computed result.

---

## Infrastructure Context

Alongside the 11 scored modules, every scan runs an **informational Infrastructure module** (`backend/app/modules/infrastructure/`) that records contextual hosting/location data for the target's resolved public IPs: ASN, hosting organization, network/CIDR, country/region and reverse DNS (when the configured provider answers).

It is deliberately **isolated from the security score**:

- It is registered in the scan pipeline but is **absent from the Risk Engine weight table** (`backend/app/risk_engine/weights.py`), so it has **zero weight**.
- It **cannot** alter the Trust Score, the verdict or the confidence.
- It **never creates security findings** — its result is display context only, and an unavailable provider degrades to an informational `unavailable` state with score 100 and no findings (a missing data point is never treated as evidence).

This invariant is enforced by tests (byte-identical `AnalysisResponse` with the module enabled vs disabled). The Infrastructure module is off by default (`INFRASTRUCTURE_ENABLED=false`).

---

## Results

All screenshots below were captured from the live application running a real scan of `https://example.com` — no mock data.

![CyberShield scan result view](docs/assets/scan-result-view.png)

The assessment result view: overall narrative, per-severity signal counts and module posture scores.

![CyberShield detailed findings](docs/assets/findings-view.png)

Severity-ranked findings with plain-language descriptions and recommendations.

![CyberShield security scan report](docs/assets/report-view.png)

The persisted report view with JSON / CSV / PDF export controls.

---

## Threat Intelligence & AI

- **Provider adapters** — Google Safe Browsing v4 (`threatMatches`) and VirusTotal v3 (URL analysis) are used only when their API keys are set.
- **Multi-provider correlation** — agreement is `consistent` / `partial` / `conflict` / `none`, computed only among *available* providers; an unavailable provider never counts as a dissenting vote.
- **Confidence/agreement signals** — aggregated confidence starts from the strongest flagging signal, adds a bonus per extra agreeing provider, and dampens on conflict.
- **Optional AI explanation** — requires `AI_ENABLED=true` and an OpenAI-compatible chat-completions endpoint. It is **disabled by default** in a fresh installation.
- **AI is score-blind** — the model receives no Trust Score, verdict or confidence, and its output is schema-validated before storage or display.
- **AI failure cannot break a scan** — disabled, unconfigured, timed out or malformed output degrades gracefully to `ai_explanation: null` with an unchanged result.

---

## Tech Stack

| Layer | Technology |
| --- | --- |
| Backend | Python 3.11+ · FastAPI · Uvicorn · Pydantic |
| Scanning | python-whois · dnspython · cryptography · httpx · requests |
| Persistence | SQLAlchemy · SQLite (PostgreSQL-compatible URL format) |
| Frontend | React 19 · Vite 8 · React Router 7 · axios |
| Testing | pytest · pytest-asyncio · pytest-cov · ESLint |
| External providers | Google Safe Browsing v4 · VirusTotal v3 · OpenAI-compatible chat endpoint (all optional) |
| Deployment | Docker Compose |

---

## Testing

Verified against the current implementation:

| Check | Result |
| --- | --- |
| Backend pytest suite | **491 passed** (`cd backend && ..\.venv\Scripts\python.exe -m pytest`) |
| Frontend test suite | **45 passed** (`cd frontend && npm test`) |
| Frontend lint | `cd frontend && npm run lint` → clean |
| Frontend production build | `cd frontend && npm run build` → successful |
| Dependency health | `pip check` → no broken requirements |
| Docker Compose contract | Loopback-only publication + SQLite persistence asserted by CI |
| System validation | Stage 1 · 3A · 3B · 3C completed — API, security abuse, reliability, browser (`docs/validation.md`) |

Tests exercise the modules, pipeline, risk engine, threat-intel adapters and correlation with injected mocks — no network or real API keys are required. The deterministic result is asserted byte-identical with AI on, off, or failing. The complete validation record — including the security model and known observations — is in [Validation](docs/validation.md) and [Security Model](docs/security-model.md).

---

## Validation Evidence

The release was validated **end-to-end**, not just unit-tested:

- **Automated regression** — 491 backend tests and 45 frontend tests, lint/build/`pip check` clean.
- **Live API smoke + security abuse** — scan lifecycle, private-host refusal, outbound guards, header footprint, logging redaction.
- **Reliability** — concurrent scans, module failure isolation, persistence across restart, snapshot/export integrity.
- **Browser validation** — the real scan journey (enter target → Trust Score → modules → Infrastructure context → findings → history → report → JSON/CSV/PDF export) verified in a live browser at 1440×900, 1024×768 and 390×844.

The full record — including the honest limitations and the one defense-in-depth observation (OBS-3B-01) — is documented in [docs/validation.md](docs/validation.md) and [docs/security-model.md](docs/security-model.md). No unsupported claim is made beyond what was executed and recorded there.

---

## Installation

### Docker (recommended)

```sh
docker compose up --build
# open http://localhost
```

SQLite data persists on the host in `./data/cybershield.db`. To configure optional provider/AI keys, copy `backend/.env.example` to `backend/.env` before starting.

### Local development

```sh
# 1. Backend environment
python -m venv .venv

# Windows
.venv\Scripts\python.exe -m pip install -r backend\requirements.txt
# macOS / Linux
.venv/bin/python -m pip install -r backend/requirements.txt

# 2. Frontend dependencies
cd frontend && npm install

# 3. Start the backend (http://localhost:8000)
cd backend && ..\.venv\Scripts\python.exe -m uvicorn app.main:app --reload --port 8000

# 4. Start the frontend (http://localhost:5173)
cd frontend && npm run dev
```

No variables are *required* to run a scan. Without provider keys, CyberShield runs on local heuristics and static feeds; without `AI_ENABLED=true` and a key, no AI explanation is produced.

---

## Environment / API

All configuration is read from the environment — never hard-coded, logged or stored. See `backend/.env.example` and `backend/app/core/config.py` for the full reference.

| Variable | Default | Purpose |
| --- | --- | --- |
| `GOOGLE_SAFE_BROWSING_API_KEY` | *(empty)* | Enables the Safe Browsing provider when set |
| `VIRUS_TOTAL_API_KEY` | *(empty)* | Enables the VirusTotal provider when set |
| `AI_ENABLED` | `false` | Master switch for the optional explanation layer |
| `AI_API_KEY` / `AI_BASE_URL` / `AI_MODEL` | *(empty)* / `https://api.openai.com/v1` / `gpt-4o-mini` | OpenAI-compatible endpoint configuration |
| `CYBERSHIELD_DATABASE_URL` | `sqlite:///cybershield.db` | SQLAlchemy database URL |
| `CYBERSHIELD_CORS_ORIGINS` | local Vite dev origins | Allowed browser origins (never `*` in production) |

Key endpoints:

| Method | Path | Purpose |
| --- | --- | --- |
| GET | `/scan/{target}` · POST `/scan` | Full scan of a URL/domain (the complete pipeline) |
| GET | `/history` · `/history/{scan_id}` | List and retrieve stored scans |
| GET | `/reports/{scan_id}/{fmt}` | Export report (`json`, `csv`, `pdf`) |
| GET | `/health` | Service health check |

Standalone per-module endpoints, for single-module analysis or scripting: `/url-analysis/{url}`, `/dns/{domain}`, `/whois/{domain}`, `/ssl/{domain}`, `/headers/{domain}`, `/reputation/{domain}`, `/typosquatting/{domain}`, `/brand-detection/{domain}`, `/threatintel/{domain}`, and `/ports/{host}` (port exposure check — standalone only, not part of the scan pipeline).

Scan targets are capped at 2048 characters; exports are generated from the stored snapshot — never by rescanning.

---

## Limitations

- **External providers require keys and availability.** Without keys, threat-intel runs on local heuristics only; VirusTotal free-tier limits apply (≈4 req/min, 500 req/day — one request per scan, no retries).
- **AI is opt-in.** It is a third-party dependency, disabled by default, and strictly presentational.
- **Heuristic scope.** Reputation, phishing, typosquatting and blacklist checks detect known signals, not all possible threats.
- **WHOIS availability varies by registry.** An unavailable lookup is treated as informational, not suspicious.
- **Single-user, no authentication.** CyberShield runs as a local/portfolio deployment, not a multi-tenant SaaS.
- **No rate limiting.** Rate limiting is intentionally absent from the local single-user loopback release. Any non-loopback deployment requires a separate security architecture review.
- **No database migration/backup tooling.** Schema is initialized idempotently (`init_db` → `create_all`); a migration/backup strategy is deferred for future long-lived or multi-user deployment.
- **CI validates the release contract, not every system behavior.** GitHub Actions runs the backend suite, frontend lint/build/tests, the Compose loopback/SQLite boundary assertion and a committed-secret scan; browser/system-level validation remains a manual release step (recorded in `docs/validation.md`).
- **Frontend dependency audit finding.** `npm audit` reports one pre-existing high-severity vulnerability in the frontend dependency tree — tracked as a security-maintenance follow-up, with no arbitrary package upgrades.

---

## Roadmap

### v1 — Released

Validated full assessment pipeline: **11 scored security modules + 1 informational Infrastructure context**, deterministic Risk Engine, threat-intelligence correlation, optional AI explanations, history/persistence, JSON/CSV/PDF reports, React frontend, **491 backend + 45 frontend tests**, automated CI (backend, frontend, Docker boundary contract, committed-secret scan), Docker Compose loopback-only deployment. System validation recorded in [docs/validation.md](docs/validation.md).

### v1.1+ — Future work

Not yet implemented:

- Additional threat-intelligence providers beyond Safe Browsing and VirusTotal
- Scheduled / recurring monitoring with alerting
- Historical risk comparison and trend views
- User accounts and authentication
- Deeper phishing model (e.g. ML-assisted heuristics)
- Enhanced correlation (provenance-tagged confidence)
- CI coverage gates and containerized runtime verification

The design document that preceded the now-implemented Infrastructure module (`docs/v1.1-infrastructure-location.md`) is retained as a historical record; the hosting/location context described there is implemented in v1 and validated.

---

## License

MIT — see [LICENSE](LICENSE).

---

## Documentation

- `backend/README.md` — deep backend technical reference (modules, scoring, providers)
- `docs/architecture.md` — architecture reference
- `docs/security-model.md` — trust boundaries, SSRF model, Infrastructure isolation, known observations
- `docs/validation.md` — recorded end-to-end system validation (Stages 1–3C)
- `docs/release-notes.md` — validated release summary
- `docs/demo-walkthrough.md` — step-by-step demo walkthrough