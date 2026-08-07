from dataclasses import dataclass


@dataclass
class PhishingFinding:
    """Legacy container for phishing analysis results.

    New code should prefer :class:`app.schemas.module_result.ModuleResult`.
    """

    domain: str
    is_phishing_suspect: bool = False
    detected_keywords: list[str] | None = None