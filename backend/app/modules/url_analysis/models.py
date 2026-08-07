from dataclasses import dataclass, field


@dataclass
class URLAnalysisDetails:
    """Structural details extracted by the URL analysis module."""

    original_url: str
    normalized_url: str
    domain: str
    is_valid: bool
    uses_https: bool
    is_ip_address: bool
    url_length: int
    subdomain_count: int


@dataclass
class URLAnalysisResult:
    """Deprecated legacy container retained for import compatibility.

    New code should use :class:`app.schemas.module_result.ModuleResult`
    together with :class:`URLAnalysisDetails`.
    """

    original_url: str
    normalized_url: str
    domain: str
    is_valid: bool
    uses_https: bool
    is_ip_address: bool
    url_length: int
    subdomain_count: int
    risk_score: int
    findings: list[str] = field(default_factory=list)
    recommendations: list[str] = field(default_factory=list)