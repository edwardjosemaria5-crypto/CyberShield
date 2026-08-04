from dataclasses import dataclass


@dataclass
class ThreatIntelFinding:
    domain: str
    threats: list[str] | None = None
