from dataclasses import dataclass


@dataclass
class HeaderFinding:
    name: str
    present: bool
    value: str | None = None
