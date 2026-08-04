import socket

DNSBL_LISTS = [
    "zen.spamhaus.org",
    "bl.spamcop.net",
    "dnsbl.sorbs.net",
    "b.barracudacentral.org",
]


def get_blacklist_status(domain: str) -> dict:
    """Check target domain or IP against public DNS blocklists (DNSBL)."""
    target = domain.replace("https://", "").replace("http://", "").split("/")[0].split(":")[0]
    blacklisted_on = []

    try:
        ip = socket.gethostbyname(target)
        reversed_ip = ".".join(reversed(ip.split(".")))

        for dnsbl in DNSBL_LISTS:
            query = f"{reversed_ip}.{dnsbl}"
            try:
                socket.gethostbyname(query)
                blacklisted_on.append(dnsbl)
            except Exception:
                pass
    except Exception:
        pass

    return {
        "domain": target,
        "is_blacklisted": len(blacklisted_on) > 0,
        "blacklisted_on": blacklisted_on,
        "total_lists_checked": len(DNSBL_LISTS),
    }
