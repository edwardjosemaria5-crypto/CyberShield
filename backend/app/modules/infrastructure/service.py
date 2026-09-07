"""Infrastructure module interface used by the ScanManager (env wiring).

Composes environment configuration with the scanner composition
(``app.modules.infrastructure.scanner``) and emits a canonical
:class:`ModuleResult`. No other module calls this one directly; the
ScanManager (via its registry) is the only orchestrator.

The provider adapter is the injection point for tests; production wiring
happens here through :func:`build_adapter`.
"""

import logging

from app.core.config import (
    INFRASTRUCTURE_ENABLED,
    INFRASTRUCTURE_PROVIDER,
    INFRASTRUCTURE_TIMEOUT_SECONDS,
)
from app.modules.infrastructure.adapter import InfrastructureAdapter
from app.modules.infrastructure.ipwhois import IpwhoisAdapter
from app.modules.infrastructure.rules import PROVIDER_IPWHOIS
from app.modules.infrastructure.scanner import scan_infrastructure_module
from app.schemas.module_result import ModuleResult

logger = logging.getLogger("cybershield.infrastructure")


def build_adapter() -> InfrastructureAdapter | None:
    """Instantiate the configured provider adapter.

    Provider selection is driven by ``INFRASTRUCTURE_PROVIDER`` (a fixed
    slug, never scan data). An unset or unknown slug returns ``None`` so the
    module degrades to an informational ``unavailable`` state. IPWHOIS is
    keyless: ``INFRASTRUCTURE_API_KEY`` is intentionally not consumed here
    (kept for future keyed providers only).
    """
    if INFRASTRUCTURE_PROVIDER == PROVIDER_IPWHOIS:
        return IpwhoisAdapter(timeout_seconds=INFRASTRUCTURE_TIMEOUT_SECONDS)
    return None


def run_infrastructure_check(domain: str) -> ModuleResult:
    """Pipeline entry point consumed by the InfrastructureScanner registry adapter.

    The feature is opt-in and off by default: unless ``INFRASTRUCTURE_ENABLED``
    is set, the module reports ``unavailable`` without resolving anything.
    """
    if not INFRASTRUCTURE_ENABLED:
        return scan_infrastructure_module(domain, adapter=None)
    return scan_infrastructure_module(domain, adapter=build_adapter())
