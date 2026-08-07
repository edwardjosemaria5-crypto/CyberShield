"""Normalize raw brand matches into a :class:`TyposquattingProfile`."""

from typing import Iterable

from app.modules.typosquatting import utils
from app.modules.typosquatting.models import BrandMatch, TyposquattingProfile
from app.modules.typosquatting.rules import SIMILARITY_LOW


def build_profile(domain: str, matches: Iterable[BrandMatch]) -> TyposquattingProfile:
    """Pick the best brand match and normalize into a profile."""
    hostname = domain.replace("https://", "").replace("http://", "").split("/")[0]
    sld = _second_level_label(hostname)
    ranked = sorted(matches, key=lambda m: m.similarity, reverse=True)
    best = ranked[0] if ranked else None
    return TyposquattingProfile(
        domain=hostname,
        sld=_strip_punycode(sld.lower()),
        matches=ranked,
        best_match=best if best and best.similarity >= SIMILARITY_LOW else None,
    )


def extract_sld(hostname: str) -> str:
    """Return the second-level label of a hostname (or the sole label)."""
    hostname = hostname.replace("https://", "").replace("http://", "").split("/")[0].split(":")[0].strip().lower()
    return _strip_punycode(_second_level_label(hostname))


def _second_level_label(hostname: str) -> str:
    parts = hostname.strip().rstrip(".").split(".")
    return parts[-2] if len(parts) >= 2 else parts[0]


def _strip_punycode(label: str) -> str:
    """Render a punycode label as ASCII-only when it is not plain ASCII."""
    if label.startswith("xn--"):
        try:
            return label.encode("ascii").decode("idna")
        except (UnicodeDecodeError, UnicodeError):
            return label
    return label


def has_homograph_characters(domain: str) -> bool:
    """Whether the domain contains any confusable non-ASCII character."""
    return utils.has_unicode(domain.replace("https://", "").split("/")[0])