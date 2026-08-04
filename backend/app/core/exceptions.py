class CyberShieldError(Exception):
    """Base application exception."""


class ScanError(CyberShieldError):
    """Raised when a scan cannot be completed."""
