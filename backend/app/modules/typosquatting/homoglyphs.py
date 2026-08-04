HOMOGLYPH_MAP = {
    "a": ["4", "@"],
    "e": ["3"],
    "i": ["1", "!"],
    "o": ["0"],
    "s": ["5", "$"],
    "l": ["1", "I"],
}


def find_homoglyphs(domain: str) -> list[str]:
    """Generate lookalike character homoglyph variations for a domain."""
    parts = domain.split(".")
    name = parts[0]
    tld = ".".join(parts[1:]) if len(parts) > 1 else "com"
    variations = set()

    for i, char in enumerate(name):
        if char in HOMOGLYPH_MAP:
            for sub in HOMOGLYPH_MAP[char]:
                homo_name = name[:i] + sub + name[i + 1:]
                variations.add(f"{homo_name}.{tld}")

    return list(variations)[:10]
