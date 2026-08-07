"""Typosquatting evaluation rules: thresholds, penalties, technique labels."""

MODULE_NAME = "typosquatting"
DEFAULT_CONFIDENCE = 92

# Similarity thresholds (0-100) that classify a brand match.
SIMILARITY_CRITICAL = 92
SIMILARITY_HIGH = 82
SIMILARITY_LOW = 65

# Penalty deducted from the base score for the best match.
PENALTY_CRITICAL = 60
PENALTY_HIGH = 35
PENALTY_LOW = 12

# Extra penalty for especially dangerous attack techniques.
HOMOGRAPH_PENALTY = 10

# Human-readable technique names used in findings and details.
TECHNIQUE_LABELS = {
    "exact": "Exact Match",
    "homograph": "Unicode Homograph",
    "substitution": "Character Substitution",
    "keyboard": "Keyboard Adjacent Substitution",
    "transposition": "Transposed Characters",
    "repeated": "Repeated Character",
    "missing": "Missing Character",
    "extra": "Extra Character",
    "similar": "Similar Domain",
}

# Techniques that are unambiguous evidence of deliberate impersonation.
DELIBERATE_TECHNIQUES = {"homograph", "substitution", "keyboard"}
