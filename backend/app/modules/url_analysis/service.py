from dataclasses import asdict

from .scanner import URLAnalyzer, scan_url_analysis_module


def run_url_analysis_check(url: str):
    return asdict(scan_url_analysis_module(url))


class URLAnalysisService:
    def __init__(self):
        self.analyzer = URLAnalyzer()

    def scan(self, url: str):
        return asdict(self.analyzer.analyze(url))
