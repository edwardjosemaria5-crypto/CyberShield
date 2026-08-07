from app.schemas.module_result import ModuleResult

from .scanner import URLAnalyzer, scan_url_analysis_module


def run_url_analysis_check(url: str) -> ModuleResult:
    return scan_url_analysis_module(url)


class URLAnalysisService:
    def __init__(self):
        self.analyzer = URLAnalyzer()

    def scan(self, url: str) -> ModuleResult:
        return self.analyzer.analyze(url)