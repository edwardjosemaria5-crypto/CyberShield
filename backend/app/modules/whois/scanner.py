import whois


def scan_whois_module(domain: str):
    try:
        data = whois.whois(domain)
        return {
            "domain": domain,
            "registrar": data.registrar,
            "creation_date": str(data.creation_date),
            "expiration_date": str(data.expiration_date),
            "name_servers": data.name_servers,
        }
    except Exception as exc:
        return {"error": str(exc)}
