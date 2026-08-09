"""Scan identifier generation for the CyberShield pipeline."""

import secrets
from datetime import datetime, timezone


def generate_scan_id() -> str:
    """Return a unique, human-readable scan identifier.

    Format: ``CS-YYYY-XXXXXXXXXXXX`` (e.g. ``CS-2026-8F4A2C910B7D``). The
    suffix draws 48 bits of cryptographically strong randomness, making
    collisions effectively impossible at any realistic scan volume.
    """
    year = datetime.now(timezone.utc).year
    return f"CS-{year}-{secrets.token_hex(6).upper()}"
