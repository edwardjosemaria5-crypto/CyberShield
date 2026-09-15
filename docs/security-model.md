# CyberShield Security Model

This document describes the security model of the **validated CyberShield v1
release** (`8a72f64`). It documents only behavior that is implemented and
verified in the codebase or the recorded system validation
(see [Validation](validation.md)); it does not claim protections that do not
exist.

---

## 1. Security Philosophy

CyberShield is a **passive, defensive assessment platform**. Its design
priorities, in order:

1. **Never make an internal or arbitrary connection.** Every outbound request
   to a scan-derived destination is validated and pinned before it is made.
2. **Never treat missing evidence as a threat signal.** A failing module,
   provider or lookup degrades to an informational/unavailable state and can
   never fabricate a malicious verdict.
3. **Keep the score deterministic and evidence-based.** The Risk Engine owns
   the Trust Score; nothing outside it (including the AI layer) can influence
   it.
4. **Prefer a safe failure.** A broken module, storage write, provider or
   explanation cannot change the result the user receives.
5. **Stay local.** The release deployment is single-user, loopback-bound, and
   intentionally never exposed to a LAN, the internet, or a public proxy.

---

## 2. Deployment Boundary

The current release is a local, single-user deployment. There is **no
authentication** and **no public exposure**.

| Component | Host publication (Compose) | Reachable from |
| --- | --- | --- |
| Frontend (nginx SPA) | `127.0.0.1:80:80` | This machine only |
| Backend (FastAPI/uvicorn) | `127.0.0.1:8000:8000` | This machine only |

- Inside its container the backend binds `0.0.0.0:8000`; that **internal** bind
  is for container networking and is safe only because the host publishes
  exclusively to the loopback interface.
- HTTP without TLS is acceptable **only** because the deployment is strictly
  loopback-bound. Changing a publication to `80:80` or `8000:8000` exposes the
  unauthenticated API/frontend beyond the local host and is **prohibited** for
  this release.
- Before any non-loopback deployment the architecture must be reassessed, and
  **HTTPS/TLS, HSTS, authentication, authorization, rate limiting** and
  additional exposure controls become required. The local HTTP setup is not
  suitable for public exposure.

---

## 3. Trust Boundaries

```
Browser
  │
  ▼
Local frontend (nginx, 127.0.0.1:80)      ← user-controlled input enters here
  │  CORS: http://localhost only
  ▼
Local API (FastAPI, 127.0.0.1:8000)       ← request validation, security headers
  │
  ▼
Scan orchestration (ScanManager)
  │
  ├─ Local-only modules (URL analysis, heuristics — no network contact)
  ├─ Connection-capable modules (headers, ports, SSL, infrastructure)
  │    │  resolve once → validate → pin public IP literals
  │    ▼
  │  Validated outbound destinations only
  │    ▼
  │  External providers / scan targets      ← the only external network surface
  │
  ▼
Risk Engine → Persistence (SQLite) → Reports (JSON/CSV/PDF)
```

External network access exists only through the backend security boundary:
connection-capable modules contact scan-derived hosts **only after** the
destination has been validated and pinned by the hardened networking layer.

---

## 4. Target Validation

Validation happens in two layers:

- **API / schema layer.** Scan targets are capped at **2048 characters**
  (`MAX_TARGET_LENGTH`, enforced by the `GET` route and the `AnalysisRequest`
  Pydantic schema). URL structure is validated: only `http`/`https` schemes
  with a present netloc are accepted (`validate_url`); malformed, scheme-less
  garbage is rejected up front and never triggers domain scanners.
- **Client layer.** The frontend pre-validates input (`validateTarget`) before
  any request, but the backend independently re-validates — the client check is
  a UX safeguard, not a security boundary.

Target validation does **not** include a public-host restriction at the API
boundary; the public-host boundary is enforced at connection time by the
connection-capable modules (see §5 and the known observation in §12).

---

## 5. SSRF / Outbound Connection Model

CyberShield's SSRF defense is a **defense-in-depth, connection-time boundary**:

1. **The scan API accepts a target for analysis** — `POST /scan` and
   `GET /scan/{target}` do not themselves reject private/reserved destinations.
2. **Connection-capable modules enforce the boundary.** The modules that fetch a
   user-supplied host — HTTP security headers, port scanning, SSL/TLS, and the
   informational Infrastructure module — resolve the destination **once**
   through `app/utils/networking.py` and refuse it if **any** resolved address
   is private, loopback, link-local, reserved, multicast, CGNAT
   (`100.64.0.0/10`, RFC 6598), or unspecified.
3. **Well-known private hostnames** (`localhost`, `localhost.localdomain`,
   `local`, `*.localhost`, `*.local`) are refused without even resolving.
4. **Ambiguous non-canonical numeric hosts** (e.g. `2130706433`, `0x7f000001`,
   `0177.0.0.1`, `127.1`) are refused because their resolution is
   OS-dependent and can silently collapse to a private address.
5. **URL userinfo** (`user:pass@host`) is stripped before host extraction so it
   can never disguise the destination host.
6. **Resolution failure is not misclassified.** A host that fails to resolve is
   handled by the module's own error path; no connection is made without a
   successful validated resolution.

The enforcement is deliberately at the modules that actually open connections.
Passive modules (DNS, WHOIS lookups via public registries, heuristics) do not
contact the target and do not need the guard.

---

## 6. DNS Resolution and IP Pinning

`app/utils/networking.py` provides the single authoritative resolution path for
outbound connections, designed to close the DNS-rebinding/TOCTOU window:

- **`resolve_public_host(host)`** resolves a destination once and returns a
  `ResolvedTarget` carrying `host` (for TLS SNI, `Host` header and certificate
  verification) plus the **validated public IP literals** that callers must
  connect to.
- Callers connect to those pinned literals and **never re-resolve the
  hostname** at connect time, so a name that answers public during validation
  cannot answer private at connect.
- Blocks are **all-or-nothing**: if any resolved record is non-public, the whole
  host is refused.
- IPv4 is ordered before IPv6 for deterministic connection order.
- Redirect chains are re-validated and re-pinned at **every hop** and stopped
  after a maximum hop count.
- The `ssl`/`headers`/`ports` modules use this pinned path; tests assert that a
  hostname, even behind userinfo or a rebinding scenario, cannot reach a
  private destination.

---

## 7. Module Failure Isolation

Every scanner returns a canonical `ModuleResult`. The ScanManager wraps each
module so a single failure can never poison a scan:

| Failure | Behavior |
| --- | --- |
| Module raises | Replaced with `ModuleResult(status="error", score=0, confidence=0)`; pipeline continues; errored weight discounted by `ERROR_CONFIDENCE_PENALTY = 0.5` |
| WHOIS/registry unavailable | Informational `info` finding, zero penalty |
| External provider fails/timeout/rate-limit/404 | `unavailable` signal with typed reason, zero penalty, never a dissenting vote in correlation |
| Storage write fails | Logged and swallowed; response unchanged |
| AI disabled/unconfigured/fails/validation mismatch | `ai_explanation: null`; response otherwise byte-identical |
| No database migration/backup tooling | Schema initialized idempotently; migration/backup deferred |

Design invariant: **a failure to obtain evidence is never evidence of
maliciousness.**

---

## 8. Logging Redaction

- All configuration, including provider/AI keys, is read **from the environment
  only** — never hard-coded, persisted, or logged.
- Provider and AI failures log exception **class names**, not request details,
  payloads or credentials.
- Loggers are namespaced per subsystem (`cybershield.*`).
- Target IPs resolved during a scan may appear in module logs only as part of
  scan output; no secret material is ever written to logs.

---

## 9. Infrastructure Isolation

The Infrastructure module is **informational context only**. Its isolation is
structural, not conventional, and is enforced in two places:

1. **Absence from the weight table.** `infrastructure` is deliberately absent
   from `MODULE_WEIGHTS` (`backend/app/risk_engine/weights.py`), and the scorer
   skips any module without a weight. It therefore has **zero weight**.
2. **Zero-impact result shape.** In every state (available, unavailable,
   disabled) it reports score 100 / confidence 100 and **no findings**; its data
   lives in `ModuleResult.details.infrastructure` for display only.

Consequences, all verified by tests:

- Infrastructure **cannot** alter the Trust Score, the verdict or the
  confidence.
- Infrastructure **never creates security findings** and never changes any
  other module's result.
- The `AnalysisResponse` is **byte-identical** whether the module is enabled or
  disabled.
- If `INFRASTRUCTURE_ENABLED` is off (the default) or no provider is configured,
  the module reports an informational `unavailable` profile without resolving
  anything.

Infrastructure is **not** a "12th scored module".

---

## 10. Reporting and Persistence

- Scans are persisted to SQLite by a unique `scan_id`; reports are always
  generated from the **stored snapshot**, never by rescanning.
- Report export routes validate the scan id against `^[A-Za-z0-9-]{1,64}$`
  (404 otherwise) and the format against the allowlist `json|csv|pdf`
  (422 otherwise). The download filename is built only from the validated scan
  id.
- CSV exporters apply **formula-injection guards**; PDF uses a bounded,
  server-side render.
- Exports set `X-Content-Type-Options: nosniff` and `Cache-Control: no-store`.
- A storage failure degrades to a logged, swallowed exception — it cannot
  change the response the user receives.

---

## 11. Security Headers

- **API responses** (global middleware, `backend/app/core/security.py`):
  `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`,
  `X-Frame-Options: DENY`. Route-level headers (e.g. report exports) win over
  the middleware defaults.
- **Frontend responses** (`frontend/nginx.conf`): `Content-Security-Policy`
  (`default-src 'self'; script-src 'self'` …), `X-Content-Type-Options`,
  `X-Frame-Options: SAMEORIGIN`, `Referrer-Policy:
  strict-origin-when-cross-origin`, on all responses including `/assets/`.
- **CORS** is an allowlist (`CYBERSHIELD_CORS_ORIGINS`, default local Vite dev
  origins; `http://localhost` in Docker). It is never `*`.
- HSTS is intentionally not set on the plain-HTTP loopback container; HSTS
  belongs at the terminating TLS layer of any future non-loopback deployment.

---

## 12. Known Defense-in-Depth Observation

The API accepts a scan target for analysis without independently rejecting
private/reserved destinations. Enforcement of the outbound boundary sits at the
module/connection layer. This was observed during system validation and is
recorded exactly:

```text
OBS-3B-01

POST /scan (and GET /scan/{target}) accepts private/reserved targets at the
API boundary.

Connection-level modules refuse those destinations.

No internal connection or exfiltration was demonstrated.

No remediation was performed during validation.
```

This is by-design defense in depth, **not** a confirmed exploitable SSRF: the
modules that can actually open a connection refuse non-public destinations
before any connection is made, independent of what the `/scan` API accepted.
The observation is retained as an explicit boundary to be re-reviewed before
any future multi-user or non-loopback deployment. It is **not** fixed in this
release.

---

## 13. Current Limitations

These are the honest constraints of the current release:

- **Single-user, no authentication.** Run as a local/portfolio deployment.
- **No rate limiting.** Intentionally absent for the local single-user
  loopback model; a non-loopback deployment requires a separate security review.
- **HTTP without TLS**, acceptable only because of the loopback-only boundary.
- **Infrastructure context is optional and off by default**
  (`INFRASTRUCTURE_ENABLED=false`); requiring a provider on the live network
  was not part of validation.
- **External providers require keys and availability**; without them
  threat-intel runs on local heuristics only.
- **The `/scan` API does not itself reject private/reserved targets** — the
  connection-time module boundary does (see OBS-3B-01).
- **No public/internet deployment model** is supported or implied by this
  release.