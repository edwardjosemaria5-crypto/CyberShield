# CyberShield System Validation

This document is the recorded end-to-end validation of the **CyberShield v1
release**. It states what was actually verified, how, and what the remaining
known observations are. It does not claim validations that were not performed.

---

## Validation Baseline

```text
Release checkpoint:  8a72f64 — ci(security): add automated release verification pipeline
Branch:              main
Working tree:        clean
Result:              RELEASE VALIDATION — PASS
```

Media used: the validated **read-only release checkout** was used throughout;
the running application was exercised over real HTTP (and a live browser for
Stage 3C), not through mocked controllers.

---

## Stage 1 — Environment

Verified the pristine, dependency-consistent environment required to run the
release:

| Check | Result |
| --- | --- |
| Backend dependencies | **`pip check` → clean**, no broken requirements |
| Backend automated suite | **491 passed** |
| Frontend lint | **clean** |
| Frontend production build | **successful** |
| Frontend automated suite | **45 passed** |
| Repository state | clean working tree at `8a72f64` |

---

## Stage 2 — API Smoke

Verified the live application's core contract over HTTP:

- Services start under the validated configuration.
- `GET /health` responds correctly.
- A real scan of `https://example.com` completes and returns the full
  `AnalysisResponse`: **Trust Score 85, verdict Low Risk, confidence 89%**,
  module results, severity summary and findings.
- Scan results are persisted and retrievable by `scan_id` via `/history`.
- Reports are exported from the stored snapshot as **JSON, CSV and PDF**.
- Results viewed from History match the original scan result (snapshot
  consistency).

---

## Stage 3A — Security Abuse

Verified the security-relevant boundaries with adversarial inputs:

- **SSRF / outbound-boundary testing.** Connection-capable modules (headers,
  ports, SSL, infrastructure) refuse private, loopback, link-local, reserved,
  multicast, CGNAT and well-known private hostname destinations, including
  rebinding/TOCTOU scenarios, non-canonical numeric hosts, and userinfo
  disguises. Resolution is pinned to validated public IP literals; redirect
  chains are re-validated and re-pinned per hop.
- **Security-header footprint.** API responses carry `X-Content-Type-Options`,
  `Referrer-Policy` and `X-Frame-Options`; the SPA/nginx responses carry a
  Content-Security-Policy (an observed header footprint is recorded as a
  validation remark — headers are present and consistent with the config,
  while exact value review on a public build remains a maintenance item).
- **Logging redaction.** No API keys, credentials, or provider request details
  are written to logs; failures log exception classes only.
- **Secret-free repository.** No committed credentials detected (also gated by
  CI's secret scan).
- **Result/export boundaries.** Report scan IDs are regex-validated; export
  filenames are built only from validated scan ids; CSV applies formula-injection
  guards; exports carry `no-store`/`nosniff`.

---

## Stage 3B — Reliability

Verified behavior under concurrency and failure:

- **Concurrent scans** complete without corrupting results or history; each
  scan keeps its own identity and snapshot.
- **Module failure isolation.** A failing module becomes an errored
  `ModuleResult` with reduced weight and cannot poison the scan or the score.
- **Persistence / restart.** Data written to SQLite survives application
  restart (and the Docker bind mount keeps `./data/cybershield.db` on the
  host); history is still retrievable after restart.
- **Snapshot consistency.** Stored snapshots reconstruct the exact
  `AnalysisResponse`; exports are rendered from the stored snapshot and never
  trigger a rescan.
- **Report integrity.** JSON/CSV/PDF export succeeds and content matches the
  stored scan.

---

## Stage 3C — Frontend and Browser

Verified the complete user journey in a **live browser** against the built
frontend and the real backend:

- Application startup and navigation.
- Full scan journey: enter `https://example.com` → run scan → Trust Score
  gauge → module cards → Infrastructure context → findings →
  recommendations.
- Dashboard rendering of the validated scan result (85 / Low Risk / 89%).
- History page: persisted scan listed, newest-first, retrievable.
- Report page: full stored record, overall assessment, export toolbar.
- **Exports:** JSON, CSV and PDF downloads complete from the report page.
- **Responsive validation** at three viewports:
  - **1440×900** (desktop)
  - **1024×768** (tablet)
  - **390×844** (mobile)
- Browser console/network reviewed during the journey; no application-level
  errors attributable to the released application.
- Invalid-target handling: garbage input is rejected up front and does not
  produce a confident malicious classification.

---

## Automated Regression

```text
Backend: 491 passed
Frontend: 45 passed
Lint: clean
Build: successful
pip check: clean
```

Coverage is functional/behavioral (modules, pipeline, Risk Engine, threat-intel
adapters and correlation with injected mocks, outbound guards, Infrastructure
isolation, security headers, history, reporting, export boundaries, AI
explanation invariants). No network or real provider keys are required by the
suite.

---

## Docker Validation

- `docker compose config` validates the composition.
- Host publication is asserted **loopback-only** by CI:
  - backend `127.0.0.1:8000:8000` (container target `8000`)
  - frontend `127.0.0.1:80:80` (container target `80`)
  - any published port with a non-loopback `host_ip` fails the check.
- Backend `CYBERSHIELD_DATABASE_URL` is asserted as
  `sqlite:////app/data/cybershield.db` with a bind mount to `/app/data`.
- The Docker runtime (build + run) was verified locally end-to-end.

---

## Persistence Validation

- SQLite database persists across container/application restart via the host
  bind mount (`./data/cybershield.db`).
- Stored scans and reports remain intact and readable after restart.

---

## Export Validation

- JSON: complete serialized stored analysis.
- CSV: flattened, formula-injection-guarded findings.
- PDF: server-rendered bounded document.
- All exports generated from the stored snapshot; download filenames derived
  only from the validated scan id; `nosniff` + `no-store` on responses.

---

## Responsive Validation

The shipped SPA was validated at **1440×900**, **1024×768** and **390×844**;
core pages (scan, dashboard, history, report) remain usable across viewports.

---

## Security Observations

Recorded exactly; nothing here was remediated during validation:

```text
OBS-3B-01

POST /scan (and GET /scan/{target}) accepts private/reserved targets at the
API boundary.

Connection-level modules refuse those destinations.

No internal connection or exfiltration was demonstrated.

No remediation was performed during validation.
```

Context: this is a defense-in-depth boundary — the modules that can actually
open connections refuse non-public destinations before contact. It is **not** a
confirmed exploitable SSRF. See the [Security Model](security-model.md) for the
full treatment.

---

## Environment Limitations

These reflect what the validation environment could not exercise — they are
**not** application failures:

- **Optional external provider credentials were unavailable** during
  validation. Threat-intel/Infrastructure/AI provider integrations are covered
  by mocked adapters and unit tests, not by live third-party calls.
- **Infrastructure provider configuration may be absent.** The Infrastructure
  module is off by default and was validated in its informational
  `unavailable` (or enabled-with-mock) states, not against the live ipwho.is
  service.
- A malformed-output **browser-level** test was deferred because no approved
  existing mechanism to inject a malformed third-party response into the live
  frontend was available; the equivalent backend behavior is covered by tests.

---

## Final Release Decision

```text
RELEASE VALIDATION — PASS
```

The validated release is an accurate, working base for the public v1 package.
Documentation-only packaging follows without any application change.