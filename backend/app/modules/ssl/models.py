from dataclasses import dataclass


@dataclass
class SSLFinding:
    issuer: str | None = None
    valid_from: str | None = None
    valid_to: str | None = None
