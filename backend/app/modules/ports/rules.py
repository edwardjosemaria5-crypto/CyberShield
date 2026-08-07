"""Port scanning evaluation rules for the ports module."""

MODULE_NAME = "ports"
DEFAULT_CONFIDENCE = 85

MAX_WORKERS = 15
CONNECTION_TIMEOUT = 1.0

COMMON_PORTS: dict[int, tuple[str, str, str]] = {
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

EXPOSED_SERVICE_PENALTY = 15
NORMAL_PORT_PENALTY = 5