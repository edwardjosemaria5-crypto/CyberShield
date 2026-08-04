import socket

try:
    import dns.resolver
    HAS_DNSPYTHON = True
except ImportError:
    HAS_DNSPYTHON = False


def resolve_domain(domain: str) -> dict:
    """Resolve DNS records (A, AAAA, MX, TXT, NS, CNAME) with fallback."""
    hostname = domain.replace("https://", "").replace("http://", "").split("/")[0].split(":")[0]
    records = {
        "A": [],
        "AAAA": [],
        "MX": [],
        "TXT": [],
        "NS": [],
        "CNAME": [],
        "spf_status": "Missing",
        "dmarc_status": "Missing",
    }

    if HAS_DNSPYTHON:
        resolver = dns.resolver.Resolver()
        resolver.timeout = 5
        resolver.lifetime = 5

        for qtype in ["A", "AAAA", "MX", "TXT", "NS", "CNAME"]:
            try:
                answers = resolver.resolve(hostname, qtype)
                for rdata in answers:
                    val = str(rdata).strip('"')
                    records[qtype].append(val)
            except Exception:
                pass

        # Check DMARC specifically on _dmarc.hostname
        try:
            dmarc_answers = resolver.resolve(f"_dmarc.{hostname}", "TXT")
            for rdata in dmarc_answers:
                txt_val = str(rdata).strip('"')
                if txt_val.startswith("v=DMARC1"):
                    records["TXT"].append(f"_dmarc: {txt_val}")
                    records["dmarc_status"] = "Valid"
        except Exception:
            pass
    else:
        # Socket fallback for basic A record resolution
        try:
            records["A"].append(socket.gethostbyname(hostname))
        except Exception:
            pass

    # Evaluate SPF and DMARC presence from TXT records
    for txt in records["TXT"]:
        if "v=spf1" in txt:
            records["spf_status"] = "Valid"
        if "v=DMARC1" in txt:
            records["dmarc_status"] = "Valid"

    return records
