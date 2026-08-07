"""WHOIS data retrieval.

This module is responsible ONLY for fetching the raw WHOIS record for a
domain. All interpretation (normalization, scoring, findings) happens in the
parser and intelligence layers; no scoring logic lives here.
"""

import whois as python_whois
from typing import Any


class WhoisUnavailableError(RuntimeError):
    """Raised when WHOIS data cannot be retrieved or is empty."""


def _hostname(domain: str) -> str:
    """Strip scheme, port, and path so any target form yields a hostname."""
    return domain.replace("https://", "").replace("http://", "").split("/")[0].split(":")[0].strip()


def fetch_whois(domain: str) -> Any:
    """Retrieve the raw WHOIS record for a domain.

    Raises:
        WhoisUnavailableError: if the lookup fails or returns no data.
    """
    hostname = _hostname(domain)
    try:
        data = python_whois.whois(hostname)
    except Exception as exc:  # noqa: BLE001 - provider errors are all fatal here
        raise WhoisUnavailableError(f"WHOIS lookup failed: {exc}") from exc
    if data is None:
        raise WhoisUnavailableError("WHOIS registry returned no data for the domain.")
    return data
