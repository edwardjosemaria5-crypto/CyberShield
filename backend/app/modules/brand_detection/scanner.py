"""Brand presence retrieval for the brand detection engine.

Extracts domain labels, finds brand aliases and suspicious terms, and
computes a similarity match using the typosquatting matcher. Returns raw
plain data; the parser normalizes it into a :class:`BrandDetectionProfile`.
Pure computation: no network, no scoring.
"""

from app.modules.brand_detection.brands import SUSPICIOUS_TERMS, get_brand_database
from app.modules.brand_detection.rules import ALIAS_SUBSTRING_MIN
from app.modules.typosquatting.scanner import find_brand_matches


def scan_brand_detection(
    domain: str,
    brand_database: dict | None = None,
    suspicious_terms: list[str] | None = None,
) -> dict:
    """Collect raw brand-impersonation signals for a hostname."""
    hostname = domain.replace("https://", "").replace("http://", "").split("/")[0].split(":")[0].strip()
    labels = hostname.lower().split(".")
    sld = labels[-2] if len(labels) >= 2 else labels[0]

    brands = brand_database if brand_database is not None else get_brand_database()
    terms = suspicious_terms if suspicious_terms is not None else SUSPICIOUS_TERMS

    signals = _find_brand_signals(hostname, labels, brands, terms)
    detected_terms = _find_suspicious_terms(sld, terms)

    matches = find_brand_matches(sld, brands)

    return {
        "domain": hostname,
        "sld": sld,
        "labels": labels,
        "signals": [s.model_dump() for s in signals],
        "suspicious_terms": detected_terms,
        "hyphens": sld.count("-"),
        "brand_term_combo": any(s.suspicious_terms for s in signals),
        "similarity_match": matches[0].model_dump() if matches else None,
    }


def _find_brand_signals(hostname: str, labels: list[str], brands: dict, terms: list[str]) -> list:
    """Locate brand aliases inside domain labels, with adjacent suspicious terms."""
    signals = []
    for name, entry in brands.items():
        if _is_official_domain(hostname, entry):
            continue
        aliases = [name.lower()] + [a.lower() for a in entry.get("aliases", [])]
        for alias in aliases:
            if len(alias) < ALIAS_SUBSTRING_MIN:
                continue
            for label in labels:
                alias_hits = _label_hits(label, alias)
                if not alias_hits:
                    continue
                from app.modules.brand_detection.models import BrandSignal

                nearby = _suspicious_terms_in_label(label, alias, terms)
                signals.append(
                    BrandSignal(
                        brand=name.title(),
                        matched_alias=alias,
                        context=label,
                        suspicious_terms=nearby,
                    )
                )
                break
    return signals


def _label_hits(label: str, alias: str) -> bool:
    """True when the alias appears in a label, directly or after leetspeak normalization."""
    if alias in label:
        return True
    from app.modules.typosquatting.utils import canonicalize_substitutions

    canonical = canonicalize_substitutions(label)
    return alias in canonical and canonical != label


def _is_official_domain(hostname: str, entry: dict) -> bool:
    hostname = hostname.rstrip(".").lower()
    for domain in entry.get("domains", []):
        domain = domain.lower().rstrip(".")
        if hostname == domain or hostname.endswith("." + domain):
            return True
    return False


def _suspicious_terms_in_label(label: str, alias: str, terms: list[str]) -> list[str]:
    """Suspicious terms that appear next to the alias within the same label."""
    rest = label.replace(alias, "|", 1)
    found = [t for t in terms if t in rest and len(t) >= 3]
    return sorted(set(found))


def _find_suspicious_terms(sld: str, terms: list[str]) -> list[str]:
    found = [t for t in terms if t in sld and len(t) >= 3]
    return sorted(set(found))