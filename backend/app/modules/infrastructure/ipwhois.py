"""IPWHOIS (ipwho.is) infrastructure intelligence adapter.

Wraps the free ``GET /{ip}`` lookup endpoint behind the
:class:`~app.modules.infrastructure.adapter.InfrastructureAdapter` contract.
Keyless (no API key, no authentication header), HTTPS-only, IP-literal path
parameter. The provider host ``ipwho.is`` is a fixed application constant and
the queried value is always a validated public IP literal, so no
attacker-controlled URL can ever reach this adapter.

Request / response contract:

- One HTTP GET per IP. A successful lookup returns ``HTTP 200`` with
  ``{"success": true, ...}``; an address with no data returns ``HTTP 200``
  with ``{"success": false, "message": "..."}``.
- Free tier: 1,000 requests/day per client IP; exceeding quota returns HTTP
  429 with a ``Retry-After`` hint. Commercial use is permitted on the free
  tier.
- No retries are ever issued: one attempt, then the failure is isolated.
- Redirects are NEVER followed (``follow_redirects=False`` is explicit): a
  3xx reply is treated as an unhandled HTTP status and degrades to
  ``unknown`` — it can never create a second outbound destination.

Trust rules (provider data is untrusted input):

- The payload is validated field by field; unknown fields are dropped and
  wrong types degrade to ``None`` (never coerced into a plausible value).
- Strings are trimmed and bounded to ``MAX_FIELD_LEN`` (80) so the report can
  never render an unbounded blob.
- The echoed ``ip`` MUST equal the queried literal; a mismatch is a
  ``bad_response`` (a misbehaving provider is never silently trusted).
- ``success=false`` means the provider has NO data for the address — that
  maps to ``no_analysis`` (we learned nothing), never a clean or bad verdict.
- Nothing in the response can raise the scanner's score: the module has no
  weight in ``MODULE_WEIGHTS`` and its result carries no findings by
  construction.
"""

import ipaddress
import logging
from typing import Any

import httpx

from app.modules.infrastructure.adapter import (
    InfrastructureAdapter,
    InfrastructureData,
    UnavailableData,
)
from app.modules.infrastructure.rules import MAX_FIELD_LEN, PROVIDER_IPWHOIS

logger = logging.getLogger("cybershield.infrastructure.ipwhois")

#: Fixed provider endpoint. The host is a developer constant — never derived
#: from scan data; only the validated IP is appended as the path segment.
IPWHOIS_ENDPOINT = "https://ipwho.is"


class IpwhoisAdapter(InfrastructureAdapter):
    """Keyless IPWHOIS adapter for the v1.1 infrastructure module."""

    provider = PROVIDER_IPWHOIS

    def __init__(
        self,
        timeout_seconds: float = 5.0,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        """``transport`` is injectable for tests (httpx.MockTransport)."""
        super().__init__(timeout_seconds=timeout_seconds)
        self._transport = transport

    @property
    def is_configurable(self) -> bool:
        """This provider needs no API key: it is ready whenever the module
        is enabled and the slug matches."""
        return True

    def lookup(self, ip_address: str) -> InfrastructureData | UnavailableData:
        """Query the provider for one **validated public IP literal**.

        Defense-in-depth: refuse anything that is not a well-formed IPv4/IPv6
        literal before it can be interpolated into the endpoint path. Public
        address validation happens upstream (``resolve_public_host``); this
        guard only prevents malformed values from altering the URL structure.
        """
        if not _is_ip_literal(ip_address):
            return self.unavailable(
                "invalid_target", "Only IP literals are accepted."
            )

        try:
            # ``follow_redirects=False`` is explicit (not a library-default
            # assumption): a redirecting provider must never create a second
            # outbound destination or silently follow an HTTPS downgrade.
            client_kwargs: dict[str, Any] = {
                "timeout": self.timeout_seconds,
                "follow_redirects": False,
            }
            if self._transport is not None:
                client_kwargs["transport"] = self._transport
            with httpx.Client(**client_kwargs) as client:
                response = client.get(f"{IPWHOIS_ENDPOINT}/{ip_address}")
        except httpx.TimeoutException:
            logger.warning("IPWHOIS timeout for %r", ip_address)
            return self.unavailable("timeout", "The provider did not respond in time.")
        except httpx.RequestError as exc:
            # NOTE: log only the exception class name — never the exception
            # body (request internals). This provider is keyless, but the
            # rule holds for any future keyed variant.
            logger.warning(
                "IPWHOIS request error %s for %r", type(exc).__name__, ip_address
            )
            return self.unavailable("network", "The provider could not be reached.")

        return self._parse_response(response, ip_address)

    def _parse_response(
        self,
        response: httpx.Response,
        ip_address: str,
    ) -> InfrastructureData | UnavailableData:
        if response.status_code == 429:
            return self.unavailable("rate_limited", "The provider rate-limited the request.")
        if response.status_code in {401, 403}:
            return self.unavailable("unauthorized", "The provider rejected the request.")
        if response.status_code >= 500:
            return self.unavailable("server_error", "The provider reported a server error.")
        if response.status_code != 200:
            logger.warning(
                "Unexpected IPWHOIS HTTP status %s for %r",
                response.status_code,
                ip_address,
            )
            return self.unavailable("unknown", f"Provider returned HTTP {response.status_code}.")

        try:
            payload = response.json()
        except (ValueError, TypeError):
            return self.unavailable("bad_response", "The provider returned malformed data.")

        return self._normalize(payload, ip_address)

    def _normalize(
        self,
        payload: Any,
        ip_queried: str,
    ) -> InfrastructureData | UnavailableData:
        if not isinstance(payload, dict):
            return self.unavailable(
                "bad_response", "The provider returned a non-object payload."
            )

        if payload.get("success") is not True:
            message = _text(payload.get("message")) or "The provider returned no data for this address."
            return self.unavailable("no_analysis", message)

        echoed = _text(payload.get("ip"))
        if echoed is None or echoed != ip_queried:
            return self.unavailable(
                "bad_response", "The provider echoed a different IP address."
            )

        connection = payload.get("connection")
        connection = connection if isinstance(connection, dict) else {}

        return InfrastructureData(
            ip=echoed,
            asn=_asn(connection.get("asn")),
            asn_organization=_text(connection.get("org")),
            isp=_text(connection.get("isp")),
            country=_text(payload.get("country")),
            country_code=_text(payload.get("country_code")),
            region=_text(payload.get("region")),
            source=self.provider,
        )


def _is_ip_literal(value: str) -> bool:
    """True when ``value`` is a well-formed IPv4/IPv6 literal."""
    try:
        ipaddress.ip_address(value)
    except (TypeError, ValueError):
        return False
    return True


def _text(value: Any) -> str | None:
    """Trim + bound one provider string; wrong types degrade to ``None``."""
    if not isinstance(value, str):
        return None
    text = value.strip()
    return text[:MAX_FIELD_LEN] or None


def _asn(value: Any) -> str | None:
    """Normalize an ASN to canonical ``AS{n}`` form; unrecognized → ``None``."""
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        value = str(value)
    elif not isinstance(value, str):
        return None
    text = value.strip()
    if not text:
        return None
    if text.isdigit():
        return f"AS{text}"
    upper = text.upper()
    if upper.startswith("AS") and upper[2:].isdigit():
        return upper
    return None