# CyberShield — Release Notes

A professional summary of the validated release. CyberShield is published under
the repository's **v1** narrative (the README and architecture documentation
use "CyberShield v1"; application-internal version fields are runtime metadata
and are not treated as public product versions here).

This release is a **validated local security-assessment platform**, not an
enterprise SaaS or public internet service.

---

## Validated Release

```text
Release checkpoint: 8a72f64 — ci(security): add automated release verification pipeline
Release validation:  RELEASE VALIDATION — PASS
Deployment model:    local, single-user, loopback-bound (Docker Compose + SQLite)
```

The complete evidence is recorded in [Validation](validation.md); the security
model is in [Security Model](security-model.md).

---

## Highlights

- Full-stack website/domain security assessment platform: FastAPI backend,
  React SPA.
- **11 scored security modules + 1 informational Infrastructure context.**
- Deterministic Risk Engine producing the Trust Score, verdict and confidence.
- Persistence, history, and JSON / CSV / PDF report export.
- Optional, strictly score-blind AI explanation layer.
- Automated CI (backend tests, frontend lint/build/tests, Docker boundary
  contract, committed-secret scan).

## Security Engineering

- **Outbound boundary with DNS pinning.** Connection-capable modules resolve
  each destination once, refuse private/loopback/link-local/reserved/multicast/
  CGNAT addresses, and connect only to validated public IP literals — closing
  the DNS-rebinding/TOCTOU window.
- **Failure isolation.** A failing module, provider, storage write or AI call
  degrades gracefully and cannot change the result the user receives.
- **Unavailable ≠ malicious.** Missing evidence is an informational signal,
  never a verdict.
- **Deterministic scoring.** The Risk Engine alone computes the score; the AI
  layer is score-blind.
- **Environment-only secrets.** Keys are never hard-coded, persisted or
  logged; failures log exception classes.
- **Security headers.** No-sniff/referrer/frame headers on the API; a
  Content-Security-Policy and header set on the SPA/nginx.
- **Iterative hardened build.** The release carries the security hardening
  tracks (defensive headers, IP pinning, bounded outbound behavior,
  informational Infrastructure isolation) to a validated state.

## Assessment Pipeline

```
Target → URL normalization → host/domain validation → URL analysis →
11 scored security modules + 1 informational Infrastructure context →
deterministic Risk Engine → persistence → dashboard / history / reports
```

Scored modules: URL structure, reputation, WHOIS, DNS, SSL/TLS, HTTP security
headers, typosquatting, brand detection, threat intelligence (local heuristics
+ optional Google Safe Browsing v4 / VirusTotal v3), blacklist, phishing
heuristics.

## Reporting and Persistence

- Every scan stored by `scan_id` in SQLite; history paginated newest-first.
- Reports rendered from the **stored snapshot** — never by rescanning.
- JSON, CSV (formula-injection-guarded) and PDF export.

## Infrastructure Context

- Informational hosting/location context (ASN, hosting organization,
  network/CIDR, country/region) for the scanned domain's resolved public IPs.
- **Zero weight.** Absent from the Risk Engine weight table; cannot alter the
  Trust Score, confidence or findings; **not** a 12th scored module.
- Off by default (`INFRASTRUCTURE_ENABLED=false`); unavailable state is an
  informational profile with no penalty.

## Automated Verification

`.github/workflows/ci.yml` runs on every push/PR:

| Job | Verifies |
| --- | --- |
| Backend | install, `pip check`, backend test suite — **491 passed** |
| Frontend | `npm ci`, lint, production build, **45 frontend tests** |
| Docker boundary | Compose validity + loopback-only publication + SQLite path/mount contract |
| Secret scan | no committed credential patterns in tracked files |

Runtime image-level checks remain a manual release step (system validation).

## System Validation

- **Stage 1 — Environment:** 491 backend + 45 frontend tests, lint/build/
  `pip check` clean.
- **Stage 2 — API smoke:** live scan of `https://example.com` →
  **Trust Score 85 / Low Risk / 89%**; persistence, history, JSON/CSV/PDF
  export verified.
- **Stage 3A — Security abuse:** outbound-boundary refusals, header footprint,
  log redaction, secret-free repo, export boundaries.
- **Stage 3B — Reliability:** concurrent scans, module failure isolation,
  persistence after restart, snapshot and export integrity.
- **Stage 3C — Browser:** full scan→dashboard→history→report→export journey in
  a live browser at **1440×900, 1024×768 and 390×844**.

## Known Observations

```text
OBS-3B-01
POST /scan (and GET /scan/{target}) accepts private/reserved targets at the
API boundary. Connection-level modules refuse those destinations. No internal
connection or exfiltration was demonstrated. No remediation was performed
during validation.
```

The outbound boundary is enforced at the connection-capable modules
(defense in depth), reviewed before any future non-loopback deployment.
No claim is made that the `/scan` API rejects every private/reserved target
before processing.

## Current Deployment Boundary

- Single-user, no authentication, no public exposure.
- Frontend `127.0.0.1:80:80`; backend `127.0.0.1:8000:8000`; SQLite on the
  host at `./data/cybershield.db`.
- HTTP without TLS is intentional and valid **only** inside this loopback
  boundary. Non-loopback deployment requires a security architecture review
  (TLS/HSTS, authentication, authorization, rate limiting) and is out of scope
  for this release.

## Deferred Work

- Additional threat-intelligence providers.
- Scheduled/recurring monitoring and alerting.
- Historical risk comparison and trend views.
- User accounts and authentication.
- Deeper phishing modeling and enhanced correlation.
- CI coverage gates and containerized runtime verification.
- Browser-level malformed-provider/system checks that required unapproved
  test tooling.
- Live third-party provider integration tests (validated via mocked adapters
  instead).

No Git tag was created for this documentation release; tagging is a separate,
explicit decision.