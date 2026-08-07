"""Configurable brand database for impersonation detection.

The database maps each well-known brand to its canonical domain(s) and
impersonation-relevant aliases. It is plain data with no import-time
dependencies, so both the typosquatting (similarity) and brand detection
(keyword/impersonation) modules can share it without circular imports.

Configuration: set ``CYBERSHIELD_BRANDS_FILE`` to a JSON file path with the
same shape as :data:`BRAND_DATABASE` to add or override brands at runtime::

    {
      "acme": {"domains": ["acme.com"], "aliases": ["acme"]}
    }
"""

import json
import logging
import os
from typing import Any

logger = logging.getLogger("cybershield.brands")

BRAND_DATABASE: dict[str, dict[str, Any]] = {
    "google": {"domains": ["google.com", "google.co.uk", "google.ca", "google.com.au"], "aliases": ["google", "gmail", "docs"]},
    "paypal": {"domains": ["paypal.com", "paypal.me"], "aliases": ["paypal"]},
    "microsoft": {"domains": ["microsoft.com", "microsoft365.com"], "aliases": ["microsoft", "msn", "windows", "office", "outlook", "onedrive"]},
    "apple": {"domains": ["apple.com", "icloud.com"], "aliases": ["apple", "icloud", "imessage"]},
    "amazon": {"domains": ["amazon.com", "amazon.co.uk", "amazon.de"], "aliases": ["amazon", "aws", "kindle", "prime"]},
    "facebook": {"domains": ["facebook.com"], "aliases": ["facebook", "fb", "meta"]},
    "netflix": {"domains": ["netflix.com"], "aliases": ["netflix"]},
    "linkedin": {"domains": ["linkedin.com"], "aliases": ["linkedin"]},
    "instagram": {"domains": ["instagram.com"], "aliases": ["instagram", "insta"]},
    "whatsapp": {"domains": ["whatsapp.com", "whatsapp.net"], "aliases": ["whatsapp"]},
    "twitter": {"domains": ["twitter.com", "x.com"], "aliases": ["twitter", "x"]},
    "dropbox": {"domains": ["dropbox.com"], "aliases": ["dropbox"]},
    "github": {"domains": ["github.com"], "aliases": ["github"]},
    "adobe": {"domains": ["adobe.com"], "aliases": ["adobe"]},
    "yahoo": {"domains": ["yahoo.com", "yahoo.co.uk"], "aliases": ["yahoo"]},
    "ebay": {"domains": ["ebay.com", "ebay.co.uk"], "aliases": ["ebay"]},
    "chase": {"domains": ["chase.com"], "aliases": ["chase"]},
    "bankofamerica": {"domains": ["bankofamerica.com"], "aliases": ["bank of america", "bofa", "boa"]},
    "wellsfargo": {"domains": ["wellsfargo.com"], "aliases": ["wells fargo"]},
    "stripe": {"domains": ["stripe.com"], "aliases": ["stripe"]},
    "coinbase": {"domains": ["coinbase.com"], "aliases": ["coinbase"]},
    "binance": {"domains": ["binance.com"], "aliases": ["binance"]},
    "steam": {"domains": ["steampowered.com"], "aliases": ["steam"]},
    "discord": {"domains": ["discord.com", "discord.gg"], "aliases": ["discord"]},
    "tiktok": {"domains": ["tiktok.com"], "aliases": ["tiktok"]},
    "roblox": {"domains": ["roblox.com"], "aliases": ["roblox"]},
    "zoom": {"domains": ["zoom.us", "zoom.com"], "aliases": ["zoom"]},
    "vpn": {"domains": ["expressvpn.com", "nordvpn.com"], "aliases": ["nordvpn", "expressvpn"]},
}

#: Terms frequently embedded in impersonation domains (login, wallet, ...).
SUSPICIOUS_TERMS: list[str] = [
    "login",
    "signin",
    "sign-in",
    "verify",
    "secure",
    "security",
    "support",
    "wallet",
    "banking",
    "update",
    "auth",
    "confirm",
    "reset",
    "billing",
    "account",
    "help",
    "password",
    "credential",
    "recover",
    "unlock",
    "alert",
    "invoice",
    "payment",
    "customer",
    "service",
    "id",
    "2fa",
    "otp",
]


def get_brand_database() -> dict[str, dict[str, Any]]:
    """Return the brand database, overlaying any configured JSON additions."""
    base = {name: dict(entry) for name, entry in BRAND_DATABASE.items()}
    override_path = os.environ.get("CYBERSHIELD_BRANDS_FILE")
    if not override_path:
        return base
    try:
        with open(override_path, encoding="utf-8") as fh:
            overlay = json.load(fh)
        base.update(overlay)
        logger.info("Loaded %d brand(s) from %s", len(overlay), override_path)
    except (OSError, json.JSONDecodeError) as exc:
        logger.warning("Ignoring brand DB overlay %s: %s", override_path, exc)
    return base


def get_brand_aliases() -> list[str]:
    """All lowercase aliases/brand names used for substring matching."""
    aliases: list[str] = []
    for name, entry in get_brand_database().items():
        aliases.append(name.lower())
        for alias in entry.get("aliases", []):
            aliases.append(alias.lower())
    return aliases


def is_official_domain(hostname: str, brand_database: dict | None = None) -> str | None:
    """Return the brand name when ``hostname`` is an official brand domain.

    Official-domain validation MUST run before any similarity calculation so
    a legitimate property (e.g. ``google.com``, ``login.microsoft.com``) is
    never classified as impersonation. A hostname is official when it equals
    a registered brand domain exactly, or when it is a subdomain of one.

    Returns the brand name (lowercase) on a match, otherwise ``None``.
    """
    hostname = _normalize_hostname(hostname)
    brands = brand_database if brand_database is not None else get_brand_database()
    for name, entry in brands.items():
        if _is_official_domain(hostname, entry):
            return name
    return None


def _is_official_domain(hostname: str, entry: dict) -> bool:
    """True when ``hostname`` equals an official domain or is a subdomain of one."""
    hostname = hostname.rstrip(".").lower()
    for domain in entry.get("domains", []):
        domain = domain.lower().rstrip(".")
        if hostname == domain or hostname.endswith("." + domain):
            return True
    return False


def _normalize_hostname(hostname: str) -> str:
    """Minimal hostname normalization for official-domain comparison.

    Mirrors the pipeline in ``typosquatting.utils.normalize_hostname``
    (scheme/port/path strip, lowercase, trailing-dot strip) without
    importing it, keeping this module free of import-time dependencies.
    """
    hostname = hostname.strip()
    if "://" in hostname:
        hostname = hostname.split("://", 1)[1]
    hostname = hostname.split("/", 1)[0]
    hostname = hostname.split(":", 1)[0]
    return hostname.rstrip(".").lower()