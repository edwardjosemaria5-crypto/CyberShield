import datetime
import socket
import ssl


def scan_ssl_module(domain: str) -> dict:
    """Scan a domain for SSL/TLS certificate details, validity, and configuration."""
    hostname = domain.replace("https://", "").replace("http://", "").split("/")[0].split(":")[0]
    context = ssl.create_default_context()

    try:
        with socket.create_connection((hostname, 443), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                cipher = ssock.cipher()
                tls_version = ssock.version()

                # Parse issuer
                issuer_dict = dict(x[0] for x in cert.get("issuer", []))
                issuer = issuer_dict.get("organizationName") or issuer_dict.get("commonName") or "Unknown"

                # Parse subject
                subject_dict = dict(x[0] for x in cert.get("subject", []))
                common_name = subject_dict.get("commonName", hostname)

                # Parse validity dates
                date_fmt = "%b %d %H:%M:%S %Y %Z"
                not_before = datetime.datetime.strptime(cert["notBefore"], date_fmt)
                not_after = datetime.datetime.strptime(cert["notAfter"], date_fmt)
                now = datetime.datetime.utcnow()
                days_left = (not_after - now).days

                # Determine status & risk
                if days_left < 0:
                    status = "Expired"
                    risk = "High"
                    grade = "F"
                elif days_left < 30:
                    status = "Expiring Soon"
                    risk = "Medium"
                    grade = "C"
                else:
                    status = "Valid"
                    risk = "Low"
                    grade = "A+" if tls_version in ("TLSv1.3", "TLSv1.2") else "B"

                # Extract Subject Alternative Names
                sans = [item[1] for item in cert.get("subjectAltName", []) if item[0] == "DNS"]

                return {
                    "domain": hostname,
                    "status": status,
                    "grade": grade,
                    "risk": risk,
                    "common_name": common_name,
                    "issuer": issuer,
                    "valid_from": cert["notBefore"],
                    "valid_until": cert["notAfter"],
                    "days_remaining": max(0, days_left),
                    "tls_version": tls_version,
                    "cipher": cipher[0] if cipher else "Unknown",
                    "subject_alt_names": sans[:10],
                }
    except ssl.SSLError as err:
        return {
            "domain": hostname,
            "status": "SSL Error",
            "grade": "F",
            "risk": "High",
            "error": f"SSL Handshake failed: {str(err)}",
        }
    except Exception as exc:
        return {
            "domain": hostname,
            "status": "Connection Failed",
            "grade": "F",
            "risk": "High",
            "error": f"Unable to establish TLS connection: {str(exc)}",
        }
