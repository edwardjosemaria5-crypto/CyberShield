from concurrent.futures import ThreadPoolExecutor
import socket

COMMON_PORTS = {
    21: ("FTP", "Medium", "Unencrypted File Transfer Protocol exposed."),
    22: ("SSH", "Low", "Secure Shell service open."),
    23: ("Telnet", "High", "Insecure Telnet protocol exposed."),
    25: ("SMTP", "Low", "Simple Mail Transfer Protocol open."),
    53: ("DNS", "Low", "Domain Name System server open."),
    80: ("HTTP", "Low", "Standard web server port open."),
    110: ("POP3", "Medium", "Unencrypted POP3 mail retrieval open."),
    143: ("IMAP", "Medium", "Unencrypted IMAP mail access open."),
    443: ("HTTPS", "Low", "Secure web server port open."),
    465: ("SMTPS", "Low", "Encrypted SMTP port open."),
    587: ("SMTP Submission", "Low", "Mail submission port open."),
    993: ("IMAPS", "Low", "Secure IMAP mail port open."),
    995: ("POP3S", "Low", "Secure POP3 mail port open."),
    3306: ("MySQL", "High", "Database server directly exposed to public internet."),
    3389: ("RDP", "High", "Remote Desktop Protocol directly exposed."),
    5432: ("PostgreSQL", "High", "PostgreSQL database directly exposed."),
    8080: ("HTTP-Proxy/Alt", "Low", "Alternative HTTP web server open."),
    8443: ("HTTPS-Alt", "Low", "Alternative HTTPS web server open."),
}


def _check_port(host: str, port: int, timeout: float = 1.0) -> dict | None:
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


def scan_ports_module(host: str) -> dict:
    """Perform concurrent TCP port scan against common target ports."""
    target_host = host.replace("https://", "").replace("http://", "").split("/")[0].split(":")[0]

    # Resolve IP address
    try:
        ip = socket.gethostbyname(target_host)
    except Exception as exc:
        return {
            "host": target_host,
            "ip": None,
            "open_ports": [],
            "total_open": 0,
            "error": f"Failed to resolve hostname: {str(exc)}",
        }

    open_ports = []
    with ThreadPoolExecutor(max_workers=15) as executor:
        futures = [executor.submit(_check_port, ip, port) for port in COMMON_PORTS.keys()]
        for future in futures:
            res = future.result()
            if res:
                open_ports.append(res)

    open_ports.sort(key=lambda x: x["port"])
    high_risk_count = sum(1 for p in open_ports if p["risk"] == "High")

    return {
        "host": target_host,
        "ip": ip,
        "open_ports": open_ports,
        "total_open": len(open_ports),
        "high_risk_ports": high_risk_count,
        "status": "Warning" if high_risk_count > 0 else "Normal",
    }
