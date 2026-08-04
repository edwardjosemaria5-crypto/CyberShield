from dataclasses import dataclass


@dataclass
class DNSFinding:
    record_type: str | None = None
    value: str | None = None
