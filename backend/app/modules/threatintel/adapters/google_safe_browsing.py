"""Google Safe Browsing adapter.

Wraps the v4 ``threatMatches:list`` endpoint behind the
:class:`~app.modules.threatintel.adapters.base.ThreatIntelAdapter` contract.

Security / reliability rules enforced here:
- The API key comes only from the caller (environment/configuration); it is
  never logged, stored, or echoed into responses.
- Responses are treated as untrusted data: every field is validated and
  normalized; unknown category labels are folded into ``unknown``.
- Timeouts, HTTP errors, rate limiting and malformed payloads all map to an
  *unavailable* signal — never to a malicious verdict.
"""

import json
import logging
from typing import Any

import httpx

from app.modules.threatintel.adapters.base import ThreatIntelAdapter
from app.schemas.threat_intel import ThreatCategory, ThreatIntelSignals
from app.utils.time import utc_now
from app.utils.urls import normalize_url, validate_url

logger = logging.getLogger("cybershield.threatintel.googlesafebrowsing")

ENDPOINT = "https://safebrowsing.googleapis.com/v4/threatMatches:list"

#: Raw API threatType labels we recognize, mapped to canonical categories.
KNOWN_THREAT_TYPES: dict[str, ThreatCategory] = {
    "MALWARE": "malware",
    "SOCIAL_ENGINEERING": "social-engineering",
    "UNWANTED_SOFTWARE": "unwanted-software",
    "POTENTIALLY_HARMFUL_APPLICATION": "malicious-download",
    "MALICIOUS_BINARY": "malicious-download",
    "API_ABUSE": "unknown",
}

#: Canonical categories (NOT raw threatType strings) that make a verdict
#: malicious vs merely suspicious.
MALICIOUS_TYPES: frozenset[str] = frozenset({"malware", "malicious-download"})
SUSPICIOUS_TYPES: frozenset[str] = frozenset({"social-engineering", "unwanted-software", "exploit"})


class GoogleSafeBrowsingAdapter(ThreatIntelAdapter):
    """Concrete adapter for the Google Safe Browsing Lookup API."""

    provider = "google-safe-browsing"

    def __init__(
        self,
        api_key: str | None = None,
        timeout_seconds: float = 5.0,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        """transport is injectable for tests (httpx.MockTransport)."""
        super().__init__(api_key=api_key, timeout_seconds=timeout_seconds)
        self._transport = transport

    def lookup(self, target: str) -> ThreatIntelSignals:
        if not self.is_configured:
            return self.unavailable("missing_api_key", "No API key configured for the provider.")

        if not validate_url(target):
            return self.unavailable("invalid_target", "Target is not a valid HTTP(S) URL.")

        payload = {"threatInfo": _build_threat_info(target)}

        try:
            client_kwargs: dict[str, Any] = {"timeout": self.timeout_seconds}
            if self._transport is not None:
                client_kwargs["transport"] = self._transport
            with httpx.Client(**client_kwargs) as client:
                response = client.post(
                    ENDPOINT,
                    params={"key": self.api_key},
                    json=payload,
                )
        except httpx.TimeoutException:
            logger.warning("Safe Browsing timeout for %r", target)
            return self.unavailable("timeout", "The provider did not respond in time.")
        except httpx.RequestError as exc:
            # NOTE: never log the exception body / URL — it embeds the API key
            # in the query string; log only the exception class name.
            logger.warning("Safe Browsing request error %s for %r", type(exc).__name__, target)
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
        if response.status_code != 200:
            logger.warning(
                "Unexpected Safe Browsing HTTP status %s for %r",
                response.status_code,
                target,
            )
            return self.unavailable("unknown", f"Provider returned HTTP {response.status_code}.")

        try:
            payload = response.json()
        except (json.JSONDecodeError, ValueError):
            return self.unavailable("bad_response", "The provider returned malformed data.")

        return self._normalize(payload, target)

    def _normalize(self, payload: dict[str, Any], target: str) -> ThreatIntelSignals:
        matches = payload.get("matches") or []
        if not isinstance(matches, list):
            return self.unavailable("bad_response", "Provider payload did not contain a matches list.")

        detections: list[dict[str, Any]] = []
        categories: list[str] = []
        evidence: list[str] = []

        for item in matches:
            if not isinstance(item, dict):
                continue
            threat_type = item.get("threatType", "")
            category = KNOWN_THREAT_TYPES.get(threat_type, "unknown")
            if category != "unknown":
                detections.append(item)
            if category not in categories:
                categories.append(category)
            display = item.get("cacheDuration") or ""
            evidence.append(
                f"{threat_type}{(' on ' + display) if display else ''}"
            )

        if not categories:
            return ThreatIntelSignals(
                provider=self.provider,
                status="available",
                malicious=False,
                suspicious=False,
                detections=0,
                categories=[],
                confidence=0,
                timestamp=utc_now(),
            )

        suspicious = any(cat in SUSPICIOUS_TYPES for cat in categories)
        malicious = any(cat in MALICIOUS_TYPES for cat in categories)

        # Categories are already normalized through KNOWN_THREAT_TYPES;
        # drop the generic "unknown" placeholder from the report.
        canonical = [c for c in categories if c != "unknown"]

        return ThreatIntelSignals(
            provider=self.provider,
            status="available",
            malicious=malicious,
            suspicious=suspicious or (not malicious and len(detections) > 0),
            detections=len(detections),
            categories=canonical,
            confidence=90 if malicious or suspicious else 10,
            evidence=evidence,
            timestamp=utc_now(),
        )


def _build_threat_info(target: str) -> dict[str, Any]:
    return {
        "threatTypes": [
            "MALWARE",
            "SOCIAL_ENGINEERING",
            "UNWANTED_SOFTWARE",
            "POTENTIALLY_HARMFUL_APPLICATION",
            "MALICIOUS_BINARY",
        ],
        "platformTypes": ["ANY_PLATFORM"],
        "threatEntryTypes": ["URL"],
        "threatEntries": [{"url": normalize_url(target)}],
    }
