"""Verdict mapping boundaries for the risk engine.

Kept thin and dependency-free; the canonical :class:`Verdict` enum and the
public :func:`app.schemas.verdict.verdict_for_score` live in the shared
schemas so the whole platform agrees on the same labels.
"""

from app.schemas.verdict import Verdict

# Re-export so consumers can rely on a single import path.
__all__ = ["Verdict"]

# Score thresholds reused by the scorer to classify trust levels.
TRUSTED_MIN = 90
LOW_RISK_MIN = 75
MODERATE_RISK_MIN = 60
SUSPICIOUS_MIN = 45
HIGH_RISK_MIN = 25