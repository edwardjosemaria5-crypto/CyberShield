from dataclasses import dataclass


@dataclass
class PortFinding:
    port: int
    open: bool
