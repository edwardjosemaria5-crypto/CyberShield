"""Similarity and detection algorithms for typosquatting analysis.

Pure functions over strings so the module is unit-testable without network
or resolver access. Every algorithm returns deterministic, plain values;
interpretation and scoring live in the parse/intelligence layers.
"""

import unicodedata


def levenshtein_distance(a: str, b: str) -> int:
    """Levenshtein edit distance (insert/delete/substitute)."""
    if len(a) < len(b):
        return levenshtein_distance(b, a)
    if len(b) == 0:
        return len(a)

    previous = list(range(len(b) + 1))
    for i, c1 in enumerate(a):
        current = [i + 1]
        for j, c2 in enumerate(b):
            insertions = previous[j + 1] + 1
            deletions = current[j] + 1
            substitutions = previous[j] + (c1 != c2)
            current.append(min(insertions, deletions, substitutions))
        previous = current
    return previous[-1]


def damerau_levenshtein(a: str, b: str) -> int:
    """Damerau-Levenshtein distance allowing adjacent transpositions."""
    if len(a) < len(b):
        return damerau_levenshtein(b, a)
    if len(b) == 0:
        return len(a)

    d = [[0] * (len(b) + 1) for _ in range(len(a) + 1)]
    for i in range(len(a) + 1):
        d[i][0] = i
    for j in range(len(b) + 1):
        d[0][j] = j
    for i in range(1, len(a) + 1):
        for j in range(1, len(b) + 1):
            cost = 0 if a[i - 1] == b[j - 1] else 1
            d[i][j] = min(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + cost)
            if i > 1 and j > 1 and a[i - 1] == b[j - 2] and a[i - 2] == b[j - 1]:
                d[i][j] = min(d[i][j], d[i - 2][j - 2] + 1)
    return d[len(a)][len(b)]


# --------------------------------------------------------------------------
# Character substitution (leetspeak look-alikes)
# --------------------------------------------------------------------------
#: look-alike character -> canonical alphabet character used for normalization
SUBSTITUTION_CANON = {
    "0": "o", "o": "o",
    "1": "l", "l": "l",
    "3": "e", "e": "e",
    "4": "a", "@": "a", "a": "a",
    "5": "s", "$": "s", "s": "s",
    "7": "t", "t": "t",
    "8": "b", "b": "b",
    "9": "g", "g": "g",
    "2": "z", "z": "z",
    "6": "g",
    "!": "i",
}

#: every known look-alike for a character (used to describe the attack)
SUBSTITUTION_LOOKALIKES = {
    "o": ["0"],
    "l": ["1", "I", "|"],
    "i": ["1", "!", "|"],
    "a": ["4", "@"],
    "e": ["3"],
    "s": ["5", "$"],
    "t": ["7"],
    "g": ["9", "6"],
    "b": ["8"],
    "z": ["2"],
    "0": ["o"],
    "1": ["l", "i"],
    "3": ["e"],
    "4": ["a"],
    "5": ["s"],
    "7": ["t"],
    "8": ["b"],
    "9": ["g"],
    "@": ["a"],
    "$": ["s"],
}

# --------------------------------------------------------------------------
# Unicode homographs: look-alike characters from other scripts
# --------------------------------------------------------------------------
HOMOGLYPH_CANON = {
    # Cyrillic
    "а": "a", "в": "b", "е": "e", "н": "h", "к": "k", "м": "m",
    "о": "o", "р": "p", "с": "c", "т": "t", "у": "y", "х": "x",
    "і": "i", "ј": "j", "ѕ": "s", "і": "i", "һ": "h", "п": "n",
    # Greek
    "α": "a", "ε": "e", "η": "n", "ι": "i", "ο": "o", "ρ": "p",
    "σ": "s", "ς": "s", "τ": "t", "υ": "u", "χ": "x", "ν": "v",
    # Misc Latin / others commonly abused
    "ı": "i", "ł": "l", "ſ": "s", "ⅼ": "l", "ⅰ": "i",
}


def canonicalize_substitutions(value: str) -> str:
    """Normalize digit/symbol look-alikes to plain letters: ``paypa1`` -> ``paypal``."""
    return "".join(SUBSTITUTION_CANON.get(ch, ch) for ch in value.strip().lower())


def canonicalize_homographs(value: str) -> str:
    """Fold confusable Unicode characters to their Latin equivalents."""
    out = []
    for ch in value.strip().lower():
        if ch in HOMOGLYPH_CANON:
            out.append(HOMOGLYPH_CANON[ch])
            continue
        decomposed = unicodedata.normalize("NFKC", ch)
        if len(decomposed) == 1 and decomposed.isascii():
            out.append(decomposed)
        else:
            out.append(ch)
    return "".join(out)


# --------------------------------------------------------------------------
# Keyboard adjacency: QWERTY neighbour map
# --------------------------------------------------------------------------
KEYBOARD_ADJACENT = {
    "q": "w", "w": "qe", "e": "wr", "r": "et", "t": "ry", "y": "tu",
    "u": "yi", "i": "uo", "o": "ip", "p": "o",
    "a": "w", "s": "ad", "d": "sf", "f": "dg", "g": "fh", "h": "gj",
    "j": "hk", "k": "jl", "l": "k",
    "z": "x", "x": "zc", "c": "xv", "v": "cb", "b": "vn", "n": "bm", "m": "n",
}


def are_keyboard_adjacent(a: str, b: str) -> bool:
    """True when ``b`` sits next to ``a`` on a standard QWERTY keyboard."""
    a = a.lower()
    b = b.lower()
    return a in KEYBOARD_ADJACENT and b in KEYBOARD_ADJACENT[a]


def has_unicode(a: str) -> bool:
    """True when a string contains any non-ASCII character."""
    return any(ord(ch) > 127 for ch in a)