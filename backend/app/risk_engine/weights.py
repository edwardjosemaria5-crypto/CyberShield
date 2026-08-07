"""Configurable module weights for the risk engine.

Weights are normalized inside :func:`app.risk_engine.scorer.compute_trust_score`
so they do not need to sum to exactly 100 here; the scorer is robust to both
missing and errored modules by re-normalizing over contributing modules.
"""

MODULE_WEIGHTS: dict[str, float] = {
    "url_analysis": 20.0,
    "reputation": 15.0,
    "whois": 5.0,
    "dns": 10.0,
    "ssl": 10.0,
    "headers": 5.0,
    "typosquatting": 10.0,
    "brand_detection": 10.0,
    "threatintel": 15.0,
    "blacklist": 10.0,
    "phishing": 10.0,
}

# Confidence multiplier applied to modules that error out so they do not
# artificially inflate the aggregated score.
ERROR_CONFIDENCE_PENALTY = 0.5