from concurrent.futures import ThreadPoolExecutor
import socket

from app.schemas.finding import Finding
from app.schemas.module_result import ModuleResult, score_to_status
from app.utils.networking import resolve_public_host
from .rules import (
    COMMON_PORTS,
    CONNECTION_TIMEOUT,
    DEFAULT_CONFIDENCE,
    EXPOSED_SERVICE_PENALTY,
    MAX_WORKERS,
    MODULE_NAME,
    NORMAL_PORT_PENALTY,
)


def _check_port(address: str, port: int, timeout: float = CONNECTION_TIMEOUT) -> dict | None:
    """Probe one literal IP/port. ``address`` must be a validated public IP
    literal (never a hostname) so DNS is never re-resolved at connect time."""
    family = socket.AF_INET6 if ":" in address else socket.AF_INET
    try:
        with socket.socket(family, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            result = sock.connect_ex((address, port))
            if result == 0:
                service, risk, note = COMMON_PORTS.get(port, ("Unknown", "Low", "Open port detected."))
                return {
                    "port": port,
                    "service": service,
                    "state": "Open",
                    "risk": risk,
                    "note": note,
                }
    except Exception:
        pass
    return None


def scan_ports_module(host: str) -> ModuleResult:
    """Perform concurrent TCP port scan against common target ports."""
    target, reason = resolve_public_host(host)
    if reason:
        return ModuleResult(
            module=MODULE_NAME,
            status="error",
            score=50,
            confidence=90,
            findings=[
                Finding(
                    title="Port scan refused",
                    severity="low",
                    description=reason,
                    recommendation="Scan a public hostname only.",
                )
            ],
            details={"host": host, "ip": None, "error": reason},
        )
    if target is None:
        return ModuleResult(
            module=MODULE_NAME,
            status="error",
            score=50,
            confidence=90,
            findings=[
                Finding(
                    title="Port scan failed",
                    severity="low",
                    description="Failed to resolve hostname.",
                    recommendation="Verify the hostname resolves correctly.",
                )
            ],
            details={"host": host, "ip": None, "error": "Failed to resolve hostname."},
        )

    open_ports = []

    def _scan_address(address: str) -> None:
        for port in COMMON_PORTS.keys():
            res = _check_port(address, port)
            if res:
                open_ports.append(res)

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = [executor.submit(_scan_address, address) for address in target.addresses]
        for future in futures:
            future.result()

    open_ports.sort(key=lambda x: x["port"])
    high_risk_ports = [p for p in open_ports if p["risk"] == "High"]

    score = 100
    findings: list[Finding] = []

    for port_info in open_ports:
        penalty = EXPOSED_SERVICE_PENALTY if port_info["risk"] == "High" else NORMAL_PORT_PENALTY
        score -= penalty
        findings.append(
            Finding(
                title=f"Open port {port_info['port']} ({port_info['service']})",
                severity=port_info["risk"].lower(),
                description=port_info["note"],
                recommendation="Close or firewall unused ports; restrict exposed services.",
            )
        )

    score = max(0, score)

    return ModuleResult(
        module=MODULE_NAME,
        status=score_to_status(score),
        score=score,
        confidence=DEFAULT_CONFIDENCE,
        findings=findings,
        details={
            "host": target.host,
            "ip": ", ".join(target.addresses),
            "open_ports": open_ports,
            "total_open": len(open_ports),
            "high_risk_ports": len(high_risk_ports),
        },
    )