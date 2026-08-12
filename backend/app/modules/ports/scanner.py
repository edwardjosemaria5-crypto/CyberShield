from concurrent.futures import ThreadPoolExecutor
import socket

from app.schemas.finding import Finding
from app.schemas.module_result import ModuleResult, score_to_status
from app.utils.networking import parse_host, validate_public_host
from .rules import (
    COMMON_PORTS,
    CONNECTION_TIMEOUT,
    DEFAULT_CONFIDENCE,
    EXPOSED_SERVICE_PENALTY,
    MAX_WORKERS,
    MODULE_NAME,
    NORMAL_PORT_PENALTY,
)


def _check_port(host: str, port: int, timeout: float = CONNECTION_TIMEOUT) -> dict | None:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            result = sock.connect_ex((host, port))
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
    target_host = parse_host(host)

    blocked = validate_public_host(target_host)
    if blocked:
        return ModuleResult(
            module=MODULE_NAME,
            status="error",
            score=50,
            confidence=90,
            findings=[
                Finding(
                    title="Port scan refused",
                    severity="low",
                    description=blocked,
                    recommendation="Scan a public hostname only.",
                )
            ],
            details={"host": target_host, "ip": None, "error": blocked},
        )

    try:
        ip = socket.gethostbyname(target_host)
    except Exception as exc:
        return ModuleResult(
            module=MODULE_NAME,
            status="error",
            score=50,
            confidence=90,
            findings=[
                Finding(
                    title="Port scan failed",
                    severity="low",
                    description=f"Failed to resolve hostname: {exc}",
                    recommendation="Verify the hostname resolves correctly.",
                )
            ],
            details={"host": target_host, "ip": None, "error": str(exc)},
        )

    open_ports = []
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = [executor.submit(_check_port, ip, port) for port in COMMON_PORTS.keys()]
        for future in futures:
            res = future.result()
            if res:
                open_ports.append(res)

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
            "host": target_host,
            "ip": ip,
            "open_ports": open_ports,
            "total_open": len(open_ports),
            "high_risk_ports": len(high_risk_ports),
        },
    )