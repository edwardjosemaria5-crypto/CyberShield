from dataclasses import dataclass


@dataclass
class WhoisFinding:
    registrar: str | None = None
    creation_date: str | None = None
    expiration_date: str | None = None
