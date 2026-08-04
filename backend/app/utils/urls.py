def ensure_scheme(url: str) -> str:
    return url if url.startswith(("http://", "https://")) else f"https://{url}"
