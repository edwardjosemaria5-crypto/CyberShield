"""Infrastructure location composition (mirrors ``blacklist/scanner.py``).

Resolves the target's public IPs, queries the provider adapter per IP and
normalizes the result into a canonical :class:`ModuleResult`. The module
never calls other modules — it resolves its own copy of the IPs; the
ScanManager owns all coordination.

Zero scoring impact by construction: the module is absent from
``MODULE_WEIGHTS``, so the scorer skips it entirely and the Trust Score,
verdict, confidence and every other module are untouched in all states.
Every failure path returns an informational ``unavailable`` profile with
score 100 and no findings (a missing data point is never a verdict).

Resolution uses the shared hardened networking layer
(``app.utils.networking``): ``parse_host()`` for target extraction,
``resolve_public_host()`` for single-pass DNS resolution with
all-or-nothing public validation.  The module never imports private
networking helpers and does not duplicate security logic.
"""

import logging

from app.core.config import INFRASTRUCTURE_MAX_IPS
from app.modules.infrastructure.adapter import (
    InfrastructureAdapter,
    InfrastructureData,
    UnavailableData,
)
from app.modules.infrastructure.models import InfrastructureProfile
from app.modules.infrastructure.rules import DEFAULT_CONFIDENCE, MAX_FIELD_LEN, MODULE_NAME
from app.schemas.module_result import ModuleResult, score_to_status
from app.utils.networking import parse_host, resolve_public_host

logger = logging.getLogger("cybershield.infrastructure")


def _bound_detail(detail: str | None, limit: int = MAX_FIELD_LEN) -> str | None:
    """Truncate an unavailable detail string so it never leaks unbounded internals."""
    if detail is None:
        return None
    return str(detail).strip()[:limit] or None


def _bound(value: str | None) -> str | None:
    """Sanitize one provider-supplied string; ``None`` stays ``None``."""
    if value is None:
        return None
    return str(value).strip()[:MAX_FIELD_LEN] or None


def _profile_for(hostname: str, ip: str, data: InfrastructureData) -> InfrastructureProfile:
    """Normalize one provider payload into the persisted profile.

    The IP we actually queried is authoritative for ``ip_address``; every
    provider value is treated as untrusted and truncated defensively.
    """
    return InfrastructureProfile(
        domain=hostname,
        ip_address=ip,
        asn=_bound(data.asn),
        asn_organization=_bound(data.asn_organization),
        isp=_bound(data.isp),
        hosting_provider=_bound(data.hosting_provider),
        network=_bound(data.network),
        reverse_dns=_bound(data.reverse_dns),
        country=_bound(data.country),
        country_code=_bound(data.country_code),
        region=_bound(data.region),
        source=_bound(data.source) or "unknown",
        status="available",
    )


def _lookup(adapter: InfrastructureAdapter, ip: str) -> InfrastructureData | UnavailableData:
    """One provider attempt; never raises, never leaks provider internals."""
    try:
        result = adapter.lookup(ip)
    except Exception as exc:  # noqa: BLE001 - provider failure is isolated
        logger.warning(
            "Infrastructure provider %s raised unexpected %s for %r",
            adapter.provider,
            type(exc).__name__,
            ip,
        )
        return adapter.unavailable("bad_response", "The provider returned an unexpected result.")
    if not isinstance(result, (InfrastructureData, UnavailableData)):
        logger.warning(
            "Infrastructure provider %s returned unexpected %s for %r",
            adapter.provider,
            type(result).__name__,
            ip,
        )
        return adapter.unavailable("bad_response", "The provider returned an unexpected result.")
    return result


def scan_infrastructure_module(
    domain: str,
    adapter: InfrastructureAdapter | None = None,
    max_ips: int | None = None,
) -> ModuleResult:
    """Resolve the target's public IPs and enrich them with provider data.

    ``adapter`` is the provider injection point for tests (defaults to
    ``None`` → ``unavailable`` with ``missing_api_key``, never a verdict).
    The module reports ``ok`` / score 100 / confidence 100 with no findings
    in every state.

    Resolution pipeline::

        raw target
            → parse_host()
            → resolve_public_host()
            → ResolvedTarget
            → validated public IP literals only
            → adapter.lookup(ip)

    The future provider boundary receives validated public IP literal
    strings.  Raw hostnames, URLs, userinfo and credentials never cross
    the adapter boundary.
    """
    hostname = parse_host(domain)

    if adapter is None or not adapter.is_configurable:
        return _unavailable_result(
            hostname,
            "missing_api_key",
            "No infrastructure provider is configured.",
        )

    resolved, refused = resolve_public_host(domain)
    if refused:
        return _unavailable_result(
            hostname,
            "invalid_target",
            refused,
        )
    if resolved is None:
        return _unavailable_result(
            hostname,
            "invalid_target",
            f"{hostname} did not resolve to any public address.",
        )

    ips = list(resolved.addresses)[:max_ips or INFRASTRUCTURE_MAX_IPS]
    if not ips:
        return _unavailable_result(
            hostname,
            "invalid_target",
            f"{hostname} did not resolve to any public address.",
        )

    first_failure: UnavailableData | None = None
    for ip in ips:
        result = _lookup(adapter, ip)
        if not isinstance(result, InfrastructureData):
            if first_failure is None:
                first_failure = result
            continue
        profile = _profile_for(hostname, ip, result)
        logger.info(
            "Infrastructure data for %s via %s: %s", hostname, profile.source, ip
        )
        return _result(hostname, profile, ips)

    failure = first_failure or adapter.unavailable(
        "unknown", f"No infrastructure data for {hostname}."
    )
    return _unavailable_result(hostname, failure.reason, _bound_detail(failure.detail), ips=ips)


def _result(
    hostname: str,
    profile: InfrastructureProfile,
    ips: list[str],
    detail: str | None = None,
) -> ModuleResult:
    """Build the canonical informational ModuleResult for the module."""
    details: dict = {
        "domain": hostname,
        "infrastructure": profile.model_dump(),
        "resolved_ips": ips,
    }
    if detail:
        details["detail"] = detail
    return ModuleResult(
        module=MODULE_NAME,
        status=score_to_status(100),
        score=100,
        confidence=DEFAULT_CONFIDENCE,
        findings=[],
        details=details,
    )


def _unavailable_result(
    hostname: str,
    reason: str,
    detail: str,
    ips: list[str] | None = None,
) -> ModuleResult:
    """Informational unavailable result: score 100, no findings."""
    profile = InfrastructureProfile(
        domain=hostname,
        status="unavailable",
        reason=reason,
    )
    return _result(hostname, profile, ips or [], detail=_bound_detail(detail))
