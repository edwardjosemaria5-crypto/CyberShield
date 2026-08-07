"""Brand similarity retrieval for the typosquatting engine.

Compares the target's second-level label against a brand database and
returns raw :class:`BrandMatch` objects. Pure computation: no network, no
scoring. The parser selects the best match and intelligence applies rules.
"""

from app.modules.typosquatting import utils
from app.modules.typosquatting.models import BrandMatch
from app.modules.typosquatting.rules import SIMILARITY_LOW


def analyze_pair(candidate: str, term: str) -> BrandMatch | None:
    """Analyze one candidate vs one brand term.

    Returns the match with its best recognized technique, or ``None`` when
    the strings are unrelated (below :data:`SIMILARITY_LOW`).
    """
    candidate = candidate.strip().lower()
    term = term.strip().lower()
    if not candidate or not term:
        return None

    if candidate == term:
        return BrandMatch(brand=term, similarity=100, technique="exact", distance=0, canonical_candidate=candidate)

    raw_distance = utils.levenshtein_distance(candidate, term)

    substitution_candidate = utils.canonicalize_substitutions(candidate)
    substitution_distance = utils.levenshtein_distance(substitution_candidate, term)

    homograph_candidate = utils.canonicalize_homographs(candidate)
    homograph_distance = utils.levenshtein_distance(homograph_candidate, term)

    best_distance = min(raw_distance, substitution_distance, homograph_distance)
    similarity = _similarity(candidate, term, best_distance)
    if similarity < SIMILARITY_LOW:
        return None

    canonical = candidate
    technique = "similar"
    if homograph_distance < raw_distance and utils.has_unicode(candidate):
        technique = "homograph"
        canonical = homograph_candidate
        best_distance = homograph_distance
    elif substitution_distance < raw_distance:
        technique = "substitution"
        canonical = substitution_candidate
        best_distance = substitution_distance
    elif candidate == term:
        technique = "exact"
    else:
        technique = _classify_edit(candidate, term, raw_distance)

    return BrandMatch(
        brand=term,
        similarity=_similarity(candidate, term, best_distance),
        technique=technique,
        distance=best_distance,
        canonical_candidate=canonical,
    )


def find_brand_matches(sld: str, brand_database: dict) -> list[BrandMatch]:
    """Compare ``sld`` against every brand name+alias; returns ranked matches."""
    matches: list[BrandMatch] = []
    for name, entry in brand_database.items():
        terms = [entry["domains"][0].split(".")[0]] + list(entry.get("aliases", []))
        for term in terms:
            match = analyze_pair(sld, term)
            if match is not None:
                match.brand = name.title()
                matches.append(match)
                break
    matches.sort(key=lambda m: m.similarity, reverse=True)
    return matches


def _similarity(candidate: str, term: str, distance: int) -> int:
    span = max(len(candidate), len(term), 1)
    return max(0, round(100 * (1 - distance / span)))


def _classify_edit(candidate: str, term: str, distance: int) -> str:
    """Name the edit operation that produced ``candidate`` from ``term``."""
    if distance == 1 and len(candidate) == len(term):
        for i, (a, b) in enumerate(zip(candidate, term)):
            if a != b and utils.are_keyboard_adjacent(a, b):
                return "keyboard"
        return "similar"

    if utils.damerau_levenshtein(candidate, term) == 1 and distance == 2:
        return "transposition"

    if len(candidate) == len(term) + 1 and _is_repeated_char(candidate, term):
        return "repeated"
    if len(candidate) == len(term) + 1:
        return "extra"
    if len(candidate) == len(term) - 1:
        return "missing"
    return "similar"


def _is_repeated_char(candidate: str, term: str) -> bool:
    """True when candidate equals term with a single character doubled."""
    for i in range(len(term)):
        if candidate == term[: i + 1] + term[i] + term[i + 1 :]:
            return True
    return False