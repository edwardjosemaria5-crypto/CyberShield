from urllib.parse import urlparse


def ensure_scheme(url: str) -> str:
    return url if url.startswith(("http://", "https://")) else f"https://{url}"


def normalize_url(url: str) -> str:
    """Strip whitespace and ensure an explicit HTTP(S) scheme."""
    return ensure_scheme(url.strip())


def extract_domain(url: str) -> str:
    """Extract the hostname portion of a URL, lowercased."""
    normalized = normalize_url(url)
    hostname = urlparse(normalized).hostname or ""
    return hostname.strip().lower()


def validate_url(url: str) -> bool:
    """Validate that the target is a well-formed HTTP(S) URL.

    Accepts a domain, an IP address, or a full URL with a hostname.
    Rejects URLs without a host, with whitespace, or non-http(s) schemes.
    """
    if not url or not isinstance(url, str):
        return False
    raw = url.strip()
    if " " in raw:
        return False
    normalized = ensure_scheme(raw)
    parsed = urlparse(normalized)
    return parsed.scheme in {"http", "https"} and bool(parsed.netloc)