from dataclasses import dataclass


@dataclass
class TypoSquattingFinding:
    domain: str
    score: int = 0
