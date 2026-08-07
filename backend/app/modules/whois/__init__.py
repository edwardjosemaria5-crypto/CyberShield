"""WHOIS Intelligence Engine.

Retrieves registration data, normalizes it into a registrar-agnostic
:class:`~app.modules.whois.models.WhoisProfile`, applies intelligence rules,
and returns a canonical :class:`~app.schemas.module_result.ModuleResult`.
"""

from app.modules.whois.intelligence import evaluate_profile
from app.modules.whois.models import WhoisProfile
from app.modules.whois.parser import parse_whois
from app.modules.whois.scanner import WhoisUnavailableError, fetch_whois
from app.modules.whois.service import run_whois_check, scan_whois_module

__all__ = [
    "WhoisProfile",
    "WhoisUnavailableError",
    "evaluate_profile",
    "fetch_whois",
    "parse_whois",
    "run_whois_check",
    "scan_whois_module",
]