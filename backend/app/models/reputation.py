from dataclasses import dataclass


@dataclass
class ReputationModel:
    domain: str
    score: int = 0
