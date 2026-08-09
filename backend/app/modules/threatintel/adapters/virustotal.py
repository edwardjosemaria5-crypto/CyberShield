"""VirusTotal URL intelligence adapter.

Wraps the v3 ``GET /urls/{url_id}`` lookup endpoint behind the
:class:`~app.modules.threatintel.adapters.base.ThreatIntelAdapter` contract.
This is the second external provider behind Google Safe Browsing; it stays
strictly inside the adapter boundary — the pipeline only ever sees the
normalized :class:`~app.schemas.threat_intel.ThreatIntelSignals`.

Confidence model (evidence-derived, deterministic and documented):

    confidence = 0                                if no flagged engines
    confidence = min(100, 30 + 15*malicious_count
                            + 10*suspicious_count) if at least one flag

- VirusTotal does NOT report a confidence value for a URL; its evidence is
  the engine tally ``last_analysis_stats`` plus per-engine verdicts. The
  formula above is monotonic in both counts and bounded to [0, 100]; we
  never claim certainty the counts do not support.
- This intentionally coexists with Google Safe Browsing's implied default
  confidence of 90 (see ``google_safe_browsing.py``): one provider's ad-hoc
  default and the other's count-derived score both normalize into the same
  ``confidence`` field, which the provider-agnostic correlation layer
  treats opaquely. A later refactor could split "provider-declared
  confidence" from "evidence-derived confidence" without touching the
  correlation algorithm.

Verdict mapping (normalization, never fabrication):

- ``malicious`` when at least one engine verdicts the URL malicious.
- ``suspicious`` when at least one engine verdicts suspicious (a malicious
  URL keeps the flag too; the correlation layer reads malicious first).
- ``detections`` = malicious + suspicious engine counts.
- Categories are inferred deterministically from flagged engine verdicts
  via the keyword table in :func:`_infer_categories`; unmatched text never
  invents a category and is simply not added to the report.
- HTTP 404 (ResourceNotFoundException): VirusTotal has NO analysis record
  of the URL. That means we learned nothing — it maps to ``unavailable``
  with the ``no_analysis`` reason and must NEVER read as a clean verdict.

Security / reliability rules:

- The API key comes only from the caller (environment); it travels only in
  the ``x-apikey`` header, and is never logged, stored, or echoed.
- No retries: one attempt; then the failure is isolated to this adapter.
- Timeouts, HTTP errors, rate limiting and malformed payloads all map to an
  *unavailable* signal — never to a malicious verdict.
"""

import base64
import logging
from typing import Any

import httpx

from app.modules.threatintel.adapters.base import ThreatIntelAdapter
from app.schemas.threat_intel import ThreatCategory, ThreatIntelSignals
from app.utils.urls import normalize_url, validate_url

logger = logging.getLogger("cybershield.threatintel.virustotal")

ENDPOINT = "https://www.virustotal.com/api/v3"

#: Upper bound for a single evidence string (engine labels and verdict text
#: can be long; the report must never render an unbounded blob).
_MAX_EVIDENCE_LEN = 160

#: Deterministic keyword → canonical category inference over flagged engine
#: verdict text. Ordered; first matching keyword wins per engine row.
CATEGORY_KEYWORDS: tuple[tuple[str, ThreatCategory], ...] = (
    ("phish", "phishing"),
    ("spam", "phishing"),
    ("trojan", "malware"),
    ("ransomware", "malware"),
    ("spyware", "malware"),
    ("stealer", "malware"),
    ("malware", "malware"),
    ("virus", "malware"),
    ("c2", "malware"),
    ("cnc", "malware"),
    ("botnet", "malware"),
    ("keylogger", "malware"),
    ("dropper", "malicious-download"),
    ("downloader", "malicious-download"),
    ("fake", "malicious-download"),
    ("exploit", "exploit"),
    ("exploit kit", "exploit"),
    ("adware", "unwanted-software"),
    ("pua", "unwanted-software"),
    ("unwanted", "unwanted-software"),
)


class VirusTotalAdapter(ThreatIntelAdapter):
    """Concrete adapter for the VirusTotal v3 URL lookup API."""

    provider = "virus_total"

    def __init__(
        self,
        api_key: str | None = None,
        timeout_seconds: float = 8.0,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        """``transport`` is injectable for tests (httpx.MockTransport)."""
        super().__init__(api_key=api_key, timeout_seconds=timeout_seconds)
        self._transport = transport

    def lookup(self, target: str) -> ThreatIntelSignals:
        if not self.is_configured:
            return self.unavailable("missing_api_key", "No API key configured for the provider.")

        if not validate_url(target):
            return self.unavailable("invalid_target", "Target is not a valid HTTP(S) URL.")

        url_id = _url_id(normalize_url(target))

        try:
            client_kwargs: dict[str, Any] = {"timeout": self.timeout_seconds}
            if self._transport is not None:
                client_kwargs["transport"] = self._transport
            with httpx.Client(**client_kwargs) as client:
                response = client.get(
                    f"{ENDPOINT}/urls/{url_id}",
                    headers={"x-apikey": self.api_key},
                )
        except httpx.TimeoutException:
            logger.warning("VirusTotal timeout for %r", target)
            return self.unavailable("timeout", "The provider did not respond in time.")
        except httpx.RequestError as exc:
            # NOTE: never log the exception body — it embeds the API key in
            # the request internals; log only the exception class name.
            logger.warning("VirusTotal request error %s for %r", type(exc).__name__, target)
            return self.unavailable("network", "The provider could not be reached.")

        return self._parse_response(response, target)

    def _parse_response(self, response: httpx.Response, target: str) -> ThreatIntelSignals:
        if response.status_code == 429:
            return self.unavailable("rate_limited", "The provider rate-limited the request.")
        if response.status_code in {401, 403}:
            return self.unavailable("unauthorized", "The provider rejected the API key.")
        if response.status_code == 400:
            return self.unavailable("invalid_target", "The provider rejected the target.")
        if response.status_code >= 500:
            return self.unavailable("server_error", "The provider reported a server error.")
        if response.status_code == 404:
            return self._handle_not_found(response)
        if response.status_code != 200:
            logger.warning(
                "Unexpected VirusTotal HTTP status %s for %r",
                response.status_code,
                target,
            )
            return self.unavailable("unknown", f"Provider returned HTTP {response.status_code}.")

        try:
            payload = response.json()
        except (ValueError, TypeError):
            return self.unavailable("bad_response", "The provider returned malformed data.")

        return self._normalize(payload)

    def _handle_not_found(self, response: httpx.Response) -> ThreatIntelSignals:
        """404: VirusTotal has NO analysis record for this URL.

        We learned nothing reliable about the target — the correct mapping
        is "unavailable", never "clean".
        """
        try:
            payload = response.json()
        except (ValueError, TypeError):
            payload = {}
        code = (payload.get("error") or {}).get("code", "")
        if code == "ResourceNotFoundException":
            return self.unavailable(
                "no_analysis",
                "VirusTotal has no analysis record for this URL; absence of a "
                "record is not a clean verdict.",
            )
        return self.unavailable("bad_response", "The provider returned an unrecognized payload.")

    def _normalize(self, payload: dict[str, Any]) -> ThreatIntelSignals:
        data = payload.get("data")
        if not isinstance(data, dict):
            return self.unavailable(
                "bad_response", "Provider payload did not contain a data object."
            )

        attributes = data.get("attributes")
        if not isinstance(attributes, dict):
            return self.unavailable(
                "bad_response", "Provider payload did not contain attributes."
            )

        stats = attributes.get("last_analysis_stats")
        if not isinstance(stats, dict):
            return self.unavailable(
                "bad_response", "Provider payload did not contain analysis stats."
            )

        malicious_count = max(0, int(stats.get("malicious", 0)))
        suspicious_count = max(0, int(stats.get("suspicious", 0)))
        harmless_count = max(0, int(stats.get("harmless", 0)))
        undetected_count = max(0, int(stats.get("undetected", 0)))

        flagged_rows = _flagged_engines(attributes.get("last_analysis_results"))
        evidence = _build_evidence(
            malicious_count,
            suspicious_count,
            harmless_count,
            undetected_count,
            flagged_rows,
            attributes,
        )
        categories = _infer_categories(flagged_rows)

        flagged_total = malicious_count + suspicious_count
        confidence = (
            0
            if flagged_total == 0
            else min(100, 30 + 15 * malicious_count + 10 * suspicious_count)
        )

        return ThreatIntelSignals(
            provider=self.provider,
            status="available",
            malicious=malicious_count > 0,
            suspicious=suspicious_count > 0,
            detections=flagged_total,
            categories=categories,
            confidence=confidence,
            evidence=evidence,
        )


def _url_id(url: str) -> str:
    """VirusTotal resource id: base64url(URL) with padding stripped."""
    encoded = base64.urlsafe_b64encode(url.encode("utf-8")).decode("ascii")
    return encoded.rstrip("=")


def _flagged_engines(results: Any) -> list[dict[str, Any]]:
    """Flatten the engine verdict map to malicious/suspicious rows only."""
    if not isinstance(results, dict):
        return []
    flagged: list[dict[str, Any]] = []
    for engine in sorted(results):
        row = results[engine]
        if not isinstance(row, dict):
            continue
        if row.get("category") in {"malicious", "suspicious"}:
            flagged.append({"engine": engine, **row})
    return flagged


def _infer_categories(flagged_rows: list[dict[str, Any]]) -> list[ThreatCategory]:
    """Deterministic canonical-category inference from flagged engine text."""
    categories: list[ThreatCategory] = []
    for row in flagged_rows:
        text = f"{row.get('result') or ''} {row.get('category') or ''}".lower()
        for keyword, category in CATEGORY_KEYWORDS:
            if keyword in text:
                if category not in categories:
                    categories.append(category)
                break
    return categories


def _build_evidence(
    malicious_count: int,
    suspicious_count: int,
    harmless_count: int,
    undetected_count: int,
    flagged_rows: list[dict[str, Any]],
    attributes: dict[str, Any],
) -> list[str]:
    """Deterministic, sanitized evidence; never raw provider dumps."""
    evidence = [
        f"Engine tally: {malicious_count} malicious, {suspicious_count} suspicious, "
        f"{harmless_count} harmless, {undetected_count} undetected"
    ]
    for row in flagged_rows:
        engine = str(row.get("engine", "?"))[:80]
        result = str(row.get("result") or row.get("category") or "flagged")[: _MAX_EVIDENCE_LEN]
        evidence.append(f"{engine}: {result}")

    reputation = attributes.get("reputation")
    if isinstance(reputation, (int, float)):
        # VT's reputation is a signed decimal; keep it as evidence only.
        evidence.append(f"VirusTotal reputation score: {reputation:+.1f}")

    last_analysis = attributes.get("last_analysis_date")
    if isinstance(last_analysis, (int, float)) and last_analysis > 0:
        evidence.append(f"Last analysis: {int(last_analysis)} (Unix epoch UTC)")
    return evidence