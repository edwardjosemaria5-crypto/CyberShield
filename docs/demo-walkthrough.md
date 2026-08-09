# CyberShield — Demo Walkthrough (3–5 minutes)

A presenter script for demonstrating CyberShield to a recruiter, a
cybersecurity professional, or a technical interviewer. Work from top to
bottom; each section says what to do, what appears on screen, and what to
SAY. The complete demo runs in ~3–5 minutes.

> Say this at the start: *"CyberShield is a website security assessment
> platform. You give it a domain or URL, it runs eleven independent checks,
> aggregates the evidence into a deterministic trust score and verdict, and
> explains every finding. Nothing here is a screenshot or a mock — everything
> you'll see is computed live."*

---

## 0. Verify the demo environment

Keep the demo to 3–5 minutes. If using Docker:

```sh
docker compose up --build        # backend on :8000, frontend on :80
```

Then open **http://localhost** (Docker) or `http://localhost:5173` (dev mode).

**Say:** *"This runs the whole stack in containers — a FastAPI backend and a
React frontend served by nginx. The scan history persists on the host in
`./data/cybershield.db`, so even a container restart keeps the data."*

## 1. Open the dashboard

The home page shows the CyberShield hero with a single scan input.

**Say:** *"One input, one workflow. No signup, no configuration — that keeps
the focus on the analysis itself. Pick any legitimate site; I'll use
example.com."*

## 2. Enter a legitimate URL

Type `https://example.com` (or `example.com` — a bare domain also works) into
the scan box.

**Say:** *"I'm scanning example.com, the IANA reserved domain, because it's a
real, safe target with real security posture — missing security headers,
recent TLD policy changes — so the results look like what you'd get for any
production site."*

## 3. Start the scan and explain timing

Hit *Scan* (or Enter). The UI shows a progress timeline.

**Say:** *"The backend normalizes and validates the URL first, then runs the
domain checks concurrently — that's why it's fast despite eleven modules: DNS
lookups, TLS handshakes and HTTP fetches happen in parallel. A typical scan
takes 10–25 seconds, depending on network."*

## 4. Explain the Trust Score

The dashboard opens with a **Trust Score gauge**.

**Say:** *"This is the headline number: a deterministic 0–100 score. It is a
weighted average of the eleven module results — URL structure, reputation,
WHOIS age, DNS posture, TLS, security headers, typosquatting, brand
impersonation, threat intel, blacklists and phishing heuristics. Weights are
re-normalized, so a module that errors doesn't poison the score. And the
whole calculation is auditable: every point traces back to evidence."*

## 5. Explain the verdict and confidence

Next to the score: e.g. **83 / Low Risk / 89% confidence**.

**Say:** *"The verdict comes from fixed boundaries — 90–100 Trusted, 75–89 Low
Risk, down to Critical below 25. Confidence is separate from the score: it's
the weighted certainty of the evidence behind it. If a module fails or a
provider is unavailable, confidence drops instead of the system pretending it
knows something it doesn't."*

## 6. Walk through the analysis modules

Show the **Module Analysis** grid (one card per module).

**Say:** *"Each card is a module: URL analysis, reputation, WHOIS, DNS, SSL/TLS,
security headers, typosquatting, brand detection, threat intelligence,
blacklist and phishing. Each shows a status badge — ok, warning or critical —
a module score and confidence. Click a card to expand its details. For
example example.com's SSL module shows a valid Cloudflare-issued certificate
with TLS 1.3; the DNS module shows the records it actually resolved."*

## 7. Show findings

Scroll to the **Findings** panel.

**Say:** *"Every module emits structured findings, ranked by severity — critical
down to informational. Each finding has a plain-language description, *why it
matters*, the concrete evidence, and a recommendation. For example.com you'll
see missing Content-Security-Policy and HSTS as high-severity, and a WHOIS
notice that the registration expires soon — that's a real, actionable signal
for domain expiring. Nothing here is templated scare-ware; moderate findings
are marked moderate."*

## 8. Explain Threat Intelligence

On the dashboard (and report), the threat-intel module card shows the
**Threat Intelligence** section.

**Say:** *"Threat intelligence runs local heuristics — phishing keyword
patterns, malware host patterns, a static blacklist feed — on every scan. On
top of that, when API keys are configured, external providers are queried:
Google Safe Browsing and VirusTotal. Each provider's verdict is normalized
into one contract, then correlated."*

## 9. Show provider / correlation information

Click the threat-intel module card / open the report's Threat Intelligence
section to show **Aggregate Threat Intelligence** and **Provider Evidence**.

**Say:** *"The correlation layer reconciles providers without knowing who they
are: agreement can be consistent, partial, conflicting, or none. If two
providers both flag a domain, confidence gets a bonus; if they conflict, the
conflict is preserved rather than averaged away. And critically: an
unavailable provider is shown as unavailable — never counted as 'safe', never
counted as a dissenting vote. Absence of evidence is not evidence of
cleanliness."*

## 10. Explain the AI layer

Show the **AI Security Explanation** card (only present when AI is enabled in
the backend).

**Say:** *"This is an optional, score-blind explanation layer. When enabled, a
language model writes a plain-language summary of *why* the results look the
way they do. It receives only an allowlisted evidence package — it never sees
the trust score, confidence or verdict, and it could never change them. The
scores are all computed deterministically before the AI is even asked."*

If AI is **disabled** (the default), **say:**

*"AI explanations are disabled by default — the scan is fully independent of
AI. That's a deliberate design property: the cyber analysis never depends on a
third-party model."*

## 11. Show recommendations

Show the **Recommendations** panel (right of Findings).

**Say:** *"Recommendations come straight from the findings — concrete, prioritized
actions like 'Implement a Content-Security-Policy to reduce XSS' or 'Renew the
domain before expiration'. This is what makes the tool useful operationally,
not just analytically."*

## 12. Open the report

Click **View Full Report** (or go to a report from History).

**Say:** *"The report page is the full record — the same evidence, plus the
overall assessment and the execution timeline, addressable by a permanent scan
ID. Anyone with the ID can re-open the report later."*

## 13. Show history

Open **History** from the sidebar/nav.

**Say:** *"Every scan is persisted on the backend — target, score, verdict,
findings, timestamp — and listed newest-first with paging. This is the
platform's memory: usable for trend checks later, and it's what makes the
reports above reproducible."*

## 14. Demonstrate JSON export

On the report page, click **JSON** in the export toolbar. A file downloads.

**Say:** *"JSON is the machine-readable form of the full report — the complete
evidence graph, exactly as the API computed it. Good for scripting, audits or
feeding other tools."*

## 15. Demonstrate CSV export

Click **CSV**.

**Say:** *"CSV is the spreadsheet-ready form, flattened per finding, with
formula-injection guards in place — because exported data ends up in analysts'
spreadsheets, where we don't want a crafted finding string to execute."*

## 16. Demonstrate PDF export

Click **PDF**. Open the file and show the page.

**Say:** *"PDF is the shareable document — the rendered report as a single file,
generated server-side from the stored snapshot. Reports are always generated
from what was stored, never by rescanning the target — exports never change
the record."*

## 17. Explain what happens when AI is disabled

If AI was never enabled: the report simply has no AI card.

**Say:** *"With AI off you lose only the prose explanation. Every score, verdict,
finding and export is identical — the tests assert that the deterministic
result is byte-identical with AI on, off, or failing."*

## 18. Demonstrate invalid URL handling

Back on the home page, enter something like `not a url` or
`ftp://example.com` and scan.

**Say:** *"Watch this: garbage in, non-result out. The URL is validated up
front. Because the target is invalid, no domain scanner ever runs — the result
reports the URL as invalid with zero confidence and no findings. It's
structurally impossible for this input to be classified as malicious. The same
guard applies to the API directly."*

## 19. Explain WHOIS-unavailable behavior

(Optional, if time allows — can be narrated instead of shown:)

**Say:** *"Some registries don't expose WHOIS data. When that happens the WHOIS
module reports an informational finding with zero penalty — \`status: info\`,
score unchanged. A lookup failure is never converted into a suspicious
verdict. That principle runs through the whole platform: unavailable evidence
is missing data, not a threat signal."*

---

## Closing line

**Say:** *"That's the loop: enter a URL → scan → evidence → trust score →
verdict → threat intelligence → optional AI explanation → report → export.
Every number is deterministic, every finding is explainable, and every failure
degrades gracefully."*

---

## Quick reference for the presenter

- Start: `docker compose up --build`, open **http://localhost**.
- Safe demo targets: `https://example.com`, `https://www.iana.org`,
  `https://github.com` (first two show rich WHOIS/DNS/header findings).
- Expected example.com result: score ~80s, **Low Risk**, findings mostly from
  missing security headers and WHOIS expiry.
- If a scan fails (e.g. network): say *"that's the failure-isolation design —
  the module errors, the scan still completes, and the score stays meaningful."*
- Suggested runtime: 3 minutes minimum, 5 minutes maximum.