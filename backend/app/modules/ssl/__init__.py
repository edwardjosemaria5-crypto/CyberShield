"""SSL/TLS Intelligence Engine.

Establishes a TLS connection, normalizes the certificate into a
:class:`~app.modules.ssl.models.SslProfile`, applies intelligence rules that
explain every finding, and returns a canonical
:class:`~app.schemas.module_result.ModuleResult`.
"""

from app.modules.ssl.intelligence import evaluate_profile
from app.modules.ssl.models import SslProfile, TlsHandshake
from app.modules.ssl.parser import parse_handshake
from app.modules.ssl.scanner import TlsUnavailableError, fetch_tls
from app.modules.ssl.service import run_ssl_check, scan_ssl_module

__all__ = [
    "SslProfile",
    "TlsHandshake",
    "TlsUnavailableError",
    "evaluate_profile",
    "fetch_tls",
    "parse_handshake",
    "run_ssl_check",
    "scan_ssl_module",
]