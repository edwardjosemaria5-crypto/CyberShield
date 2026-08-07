"""Scan identifier generation for the CyberShield pipeline."""

import secrets
from datetime import datetime, timezone


def generate_scan_id() -> str:
    """Return a unique, human-readable scan identifier.

    Format: ``CS-YYYY-XXXXXXXX`` (e.g. ``CS-2026-8F4A2C91``). The suffix
    draws 32 bits of cryptographically strong randomness, so collisions are
    negligible even at high scan volumes.
    """
    year = datetime.now(timezone.utc).year
    return f"CS-{year}-{secrets.token_hex(4).upper()}"
