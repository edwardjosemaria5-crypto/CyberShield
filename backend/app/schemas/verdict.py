from enum import Enum


class Verdict(str, Enum):
    """Overall trust verdict assigned to an analyzed URL."""

    TRUSTED = "Trusted"
    LOW_RISK = "Low Risk"
    MODERATE_RISK = "Moderate Risk"
    SUSPICIOUS = "Suspicious"
    HIGH_RISK = "High Risk"
    CRITICAL = "Critical"


def verdict_for_score(score: int) -> Verdict:
    """Map a trust score (0-100) onto a human verdict.

    Boundaries (configurable in the future via weights/verdict config):
      90-100 Trusted
      75-89  Low Risk
      60-74  Moderate Risk
      45-59  Suspicious
      25-44  High Risk
      0-24   Critical
    """
    if score >= 90:
        return Verdict.TRUSTED
    if score >= 75:
        return Verdict.LOW_RISK
    if score >= 60:
        return Verdict.MODERATE_RISK
    if score >= 45:
        return Verdict.SUSPICIOUS
    if score >= 25:
        return Verdict.HIGH_RISK
    return Verdict.CRITICAL