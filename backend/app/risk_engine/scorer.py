"""Pure scoring logic for the risk engine.

The scorer computes a single weighted trust score from a collection of
standardized :class:`~app.schemas.module_result.ModuleResult` objects.

Design rules:
- Weights always come from ``app.risk_engine.weights``.
- Modules that errored contribute a reduced effective confidence so a broken
  module cannot drag the score down through an unreliable result.
- Weights are re-normalized over the modules that actually produced a result,
  so a partially successful scan still yields a meaningful 0-100 trust score.
"""

import logging

from app.risk_engine.weights import ERROR_CONFIDENCE_PENALTY
from app.schemas.module_result import ModuleResult
from app.schemas.risk_score import RiskScore
from app.schemas.verdict import verdict_for_score

logger = logging.getLogger("cybershield.risk_engine")


def _effective_score(result: ModuleResult) -> int:
    """Apply confidence discounting to a module score."""
    confidence_factor = result.confidence / 100.0
    return round(result.score * confidence_factor)


def compute_confidence(
    results: dict[str, ModuleResult],
    weights: dict[str, float] | None = None,
) -> int:
    """Aggregate per-module confidence into a single 0-100 confidence score.

    Confidence is weighted with the same configurable module weights used
    for the trust score, and errored modules receive the same confidence
    penalty so an unreliable module cannot inflate aggregate confidence.
    """
    from app.risk_engine.weights import MODULE_WEIGHTS

    module_weights = weights if weights is not None else MODULE_WEIGHTS
    if not results:
        return 0

    total_weight = 0.0
    weighted_sum = 0.0

    for name, result in results.items():
        weight = module_weights.get(name, 0.0)
        if weight <= 0:
            continue
        if result.status == "error":
            weight *= ERROR_CONFIDENCE_PENALTY
        total_weight += weight
        weighted_sum += weight * result.confidence

    if total_weight <= 0:
        return 0
    return max(0, min(100, round(weighted_sum / total_weight)))


def compute_trust_score(
    results: dict[str, ModuleResult],
    weights: dict[str, float] | None = None,
) -> RiskScore:
    """Aggregate module results into a single weighted trust score."""
    from app.risk_engine.weights import MODULE_WEIGHTS

    module_weights = weights if weights is not None else MODULE_WEIGHTS
    if not results:
        return RiskScore(score=0, verdict=verdict_for_score(0))

    total_weight = 0.0
    weighted_sum = 0.0

    for name, result in results.items():
        weight = module_weights.get(name, 0.0)
        if weight <= 0:
            logger.debug("Skipping '%s': no configured weight", name)
            continue
        if result.status == "error":
            weight *= ERROR_CONFIDENCE_PENALTY
        total_weight += weight
        weighted_sum += weight * _effective_score(result)

    if total_weight <= 0:
        return RiskScore(score=0, verdict=verdict_for_score(0))

    score = max(0, min(100, round(weighted_sum / total_weight)))
    return RiskScore(score=score, verdict=verdict_for_score(score))