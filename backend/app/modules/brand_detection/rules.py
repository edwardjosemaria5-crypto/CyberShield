"""Brand detection rules, thresholds, and penalties."""

MODULE_NAME = "brand_detection"
DEFAULT_CONFIDENCE = 92

#: A domain label need only contain this many characters of a brand name
#: (prefix/suffix) to be considered an impersonation candidate.
ALIAS_SUBSTRING_MIN = 4

# Penalties (base score 100).
PENALTY_BRAND_AND_TERM = 40
PENALTY_BRAND_ONLY = 18
PENALTY_TERM_ONLY = 8
PENALTY_MULTIPLE_TERMS = 10
PENALTY_HYPENATED = 4

# Severity of the "Potential Brand Impersonation" finding.
SEVERITY_BRAND_AND_TERM = "critical"
SEVERITY_BRAND_ONLY = "high"
SEVERITY_TERM_ONLY = "low"