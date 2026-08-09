"""Configuration defaults for the CyberShield backend."""

import os

API_TITLE = "CyberShield API"
API_VERSION = "2.0.0"

# Database connection. SQLite by default for development; override with
# CYBERSHIELD_DATABASE_URL to point at PostgreSQL later (same SQLAlchemy
# connection string format).
DATABASE_URL = os.environ.get(
    "CYBERSHIELD_DATABASE_URL",
    "sqlite:///cybershield.db",
)

# External threat-intelligence providers.
# The API key is read from the environment only — never hardcoded, never
# persisted, never logged. Provider adapters are only instantiated when the
# key is present.
GOOGLE_SAFE_BROWSING_API_KEY = os.environ.get("GOOGLE_SAFE_BROWSING_API_KEY", "")
GOOGLE_SAFE_BROWSING_TIMEOUT_SECONDS = float(
    os.environ.get("GOOGLE_SAFE_BROWSING_TIMEOUT_SECONDS", "5.0")
)

# VirusTotal v3 (second provider). Same rules: key from the environment
# only; adapter instantiated only when the key is present. A slightly longer
# default timeout accommodates the free tier's slower responses.
VIRUS_TOTAL_API_KEY = os.environ.get("VIRUS_TOTAL_API_KEY", "")
VIRUS_TOTAL_TIMEOUT_SECONDS = float(
    os.environ.get("VIRUS_TOTAL_TIMEOUT_SECONDS", "8.0")
)


def _bounded_float(name: str, default: float, low: float, high: float) -> float:
    """Parse an env float, falling back to ``default`` when unset/invalid,
    clamping whatever survives into [low, high]."""
    raw = os.environ.get(name, "")
    try:
        value = float(raw) if raw else default
    except ValueError:
        value = default
    return max(low, min(high, value))


# Threat-intelligence correlation tuning. Initial values, NOT validated
# constants — tune after real provider data exists. Bounded so a bad env
# value can never drive confidence outside 0-100 or invert a discount.
THREAT_INTEL_AGREEMENT_BONUS = int(
    _bounded_float("THREAT_INTEL_AGREEMENT_BONUS", 10.0, 0.0, 100.0)
)
THREAT_INTEL_CONFLICT_MULTIPLIER = _bounded_float(
    "THREAT_INTEL_CONFLICT_MULTIPLIER", 0.85, 0.0, 1.0
)

# Master switch: set to "false" to disable all external provider lookups
# without removing keys from the environment.
THREAT_PROVIDER_ENABLED = os.environ.get("CYBERSHIELD_THREAT_PROVIDER_ENABLED", "true").lower() in {
    "1",
    "true",
    "yes",
    "on",
}

# ---------------------------------------------------------------------------
# AI security explanation (presentation layer only).
# The model NEVER scores anything: Trust/verdict/module scores/findings stay
# fully deterministic. When AI is disabled/unconfigured/failing the scan is
# returned without an explanation. Key is read from the environment only.
# ---------------------------------------------------------------------------
AI_ENABLED = os.environ.get("AI_ENABLED", "false").lower() in {"1", "true", "yes", "on"}
AI_PROVIDER = os.environ.get("AI_PROVIDER", "openai-compatible")
AI_MODEL = os.environ.get("AI_MODEL", "gpt-4o-mini")
AI_API_KEY = os.environ.get("AI_API_KEY", "")
AI_BASE_URL = os.environ.get("AI_BASE_URL", "https://api.openai.com/v1")
AI_TIMEOUT_SECONDS = _bounded_float("AI_TIMEOUT_SECONDS", 30.0, 5.0, 120.0)


def _bounded_int(name: str, default: int, low: int, high: int) -> int:
    raw = os.environ.get(name, "")
    try:
        value = int(raw) if raw else default
    except ValueError:
        value = default
    return max(low, min(high, value))


#: Output cap (tokens) for the explanation model; keeps cost bounded kink.
AI_MAX_TOKENS = _bounded_int("AI_MAX_TOKENS", 800, 128, 8192)

# Comma-separated browser origins allowed to call the API cross-origin.
# Development defaults match the local Vite dev server; production
# deployments must override with their own origin(s) — never "*".
BROWSER_CORS_ORIGINS = [
    origin.strip()
    for origin in os.environ.get(
        "CYBERSHIELD_CORS_ORIGINS",
        "http://localhost:5173,http://127.0.0.1:5173",
    ).split(",")
    if origin.strip()
]