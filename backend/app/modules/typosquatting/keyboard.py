KEYBOARD_MAP = {
    "a": ["q", "w", "s", "z"],
    "b": ["v", "g", "h", "n"],
    "c": ["x", "d", "f", "v"],
    "d": ["s", "e", "r", "f", "c", "x"],
    "e": ["w", "3", "4", "r", "f", "d"],
    "g": ["f", "r", "t", "h", "b", "v"],
    "i": ["u", "8", "9", "o", "k", "j"],
    "o": ["i", "9", "0", "p", "l", "k"],
    "s": ["a", "w", "e", "d", "x", "z"],
}


def keyboard_neighbors(domain: str) -> list[str]:
    """Generate keyboard proximity typo variations for a domain label."""
    parts = domain.split(".")
    if not parts:
        return []

    name = parts[0]
    tld = ".".join(parts[1:]) if len(parts) > 1 else "com"
    variations = set()

    for i, char in enumerate(name):
        if char in KEYBOARD_MAP:
            for neighbor in KEYBOARD_MAP[char]:
                typo_name = name[:i] + neighbor + name[i + 1:]
                variations.add(f"{typo_name}.{tld}")

    return list(variations)[:10]
