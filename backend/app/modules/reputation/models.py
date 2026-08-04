from dataclasses import dataclass


@dataclass
class ReputationFinding:
    domain: str
    score: int = 0
