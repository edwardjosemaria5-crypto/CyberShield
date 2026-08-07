"""HTTP security header scoring rules for the headers module."""

from app.schemas.finding import Severity

MODULE_NAME = "headers"
DEFAULT_CONFIDENCE = 95

# header name -> (severity when missing, weight contributed when present)
HEADER_DEFINITIONS: dict[str, tuple[Severity, int]] = {
    "Content-Security-Policy": ("high", 25),
    "Strict-Transport-Security": ("high", 20),
    "X-Frame-Options": ("medium", 15),
    "X-Content-Type-Options": ("medium", 15),
    "Referrer-Policy": ("low", 15),
    "Permissions-Policy": ("low", 10),
}

HEADER_RECOMMENDATIONS: dict[str, str] = {
    "Content-Security-Policy": "Implement a Content-Security-Policy header to reduce XSS attacks.",
    "Strict-Transport-Security": "Enable HSTS to force browsers to use HTTPS.",
    "X-Frame-Options": "Set X-Frame-Options to DENY or SAMEORIGIN.",
    "X-Content-Type-Options": "Set X-Content-Type-Options to nosniff.",
    "Referrer-Policy": "Configure a Referrer-Policy to protect user privacy.",
    "Permissions-Policy": "Restrict browser features using a Permissions-Policy.",
}

GRADE_THRESHOLDS = (
    (95, "A+"),
    (90, "A"),
    (80, "B"),
    (70, "C"),
    (60, "D"),
    (0, "F"),
)


def grade_for_score(score: int) -> str:
    for threshold, grade in GRADE_THRESHOLDS:
        if score >= threshold:
            return grade
    return "F"