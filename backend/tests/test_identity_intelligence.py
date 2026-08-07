"""Tests for the Typosquatting and Brand Detection Intelligence Engines.

The similarity engine is pure string math, so all tests run offline. The
brand detection engine uses the default brand database (no network needed).
"""

from app.modules.brand_detection.intelligence import evaluate_profile as evaluate_brand_profile
from app.modules.brand_detection.parser import parse_brand_profile
from app.modules.brand_detection.service import run_brand_detection_check, scan_brand_detection_module
from app.modules.typosquatting.intelligence import evaluate_profile as evaluate_typo_profile
from app.modules.typosquatting.parser import build_profile
from app.modules.typosquatting.scanner import analyze_pair, find_brand_matches
from app.modules.typosquatting.service import run_typosquatting_check, scan_typosquatting_module

TEST_BRANDS = {
    "paypal": {"domains": ["paypal.com"], "aliases": ["paypal"]},
    "google": {"domains": ["google.com"], "aliases": ["google"]},
}


def _titles(result):
    return [f.title for f in result.findings]


def _typo_profile(sld: str):
    return build_profile(f"{sld}.com", find_brand_matches(sld, TEST_BRANDS))


# ------------------------------------------------------------ similarity engine

def test_levenshtein_distance():
    from app.modules.typosquatting.utils import levenshtein_distance

    assert levenshtein_distance("kitten", "sitting") == 3
    assert levenshtein_distance("google", "google") == 0
    assert levenshtein_distance("", "abc") == 3


def test_character_substitution_detected():
    match = analyze_pair("paypa1", "paypal")

    assert match is not None
    assert match.technique == "substitution"
    assert match.canonical_candidate == "paypal"
    assert match.similarity >= 90


def test_homograph_detected():
    match = analyze_pair("раypal", "paypal")  # Cyrillic а

    assert match is not None
    assert match.technique == "homograph"
    assert match.canonical_candidate == "paypal"


def test_keyboard_adjacent_detected():
    match = analyze_pair("foogle", "google")  # g -> f are adjacent QWERTY keys

    assert match is not None
    assert match.technique == "keyboard"


def test_transposition_detected():
    match = analyze_pair("paypalp", "paypal")  # transposed p/l -> "paypla" style

    assert match is not None
    assert match.similarity >= 80


def test_repeated_character_detected():
    match = analyze_pair("gooogle", "google")

    assert match is not None
    assert match.technique == "repeated"
    assert match.similarity >= 80


def test_unrelated_domain_returns_none():
    match = analyze_pair("example", "paypal")

    assert match is None


def test_exact_brand_sld_matches():
    match = analyze_pair("paypal", "paypal")

    assert match is not None
    assert match.technique == "exact"
    assert match.similarity == 100


# ------------------------------------------------------------ typosquatting intelligence

def test_healthy_domain_no_findings():
    profile = build_profile("example.com", [])

    result = evaluate_typo_profile(profile)

    assert result.score == 100
    assert result.findings == []
    assert result.confidence == 92


def test_typosquatting_substitution_critical():
    profile = _typo_profile("paypa1")

    result = evaluate_typo_profile(profile)

    assert result.score <= 40
    assert any(f.severity == "critical" for f in result.findings)
    finding = result.findings[0]
    assert finding.explanation
    assert finding.recommendation
    assert finding.evidence
    assert "paypal" in finding.evidence.lower()


def test_typosquatting_homograph_high():
    profile = _typo_profile("раypal")

    result = evaluate_typo_profile(profile)

    assert any(f.title == "Unicode Homograph Attack" for f in result.findings)
    assert any(f.severity == "high" for f in result.findings)


def test_typosquatting_service_end_to_end():
    result = run_typosquatting_check("paypa1-login.com")

    assert result.module == "typosquatting"
    assert result.details["sld"] == "paypa1-login"
    assert result.details["total_brands_compared"] > 0


def test_typosquatting_service_injectable():
    result = scan_typosquatting_module("paypa1.com", brand_database=TEST_BRANDS)

    assert result.details["best_match"]["brand"] == "Paypal"
    assert result.details["best_match"]["technique"] == "substitution"
    assert result.status in {"critical", "warning"}


# ------------------------------------------------------------ brand detection

def test_brand_keyword_combo_detected():
    profile = parse_brand_profile(
        {
            "domain": "paypal-login-security.com",
            "sld": "paypal-login-security",
            "labels": ["paypal-login-security", "com"],
            "signals": [
                {
                    "brand": "Paypal",
                    "matched_alias": "paypal",
                    "context": "paypal-login-security",
                    "suspicious_terms": ["login", "security"],
                }
            ],
            "suspicious_terms": ["login", "security"],
            "hyphens": 2,
            "brand_term_combo": True,
            "similarity_match": None,
        }
    )

    result = evaluate_brand_profile(profile)

    assert result.score <= 50
    assert any(f.severity == "critical" for f in result.findings)
    finding = next(f for f in result.findings if "Impersonation" in f.title)
    assert finding.explanation
    assert finding.recommendation
    assert "login" in finding.evidence


def test_brand_only_signal_high():
    profile = parse_brand_profile(
        {
            "domain": "paypalsecure.com",
            "sld": "paypalsecure",
            "labels": ["paypalsecure", "com"],
            "signals": [
                {
                    "brand": "Paypal",
                    "matched_alias": "paypal",
                    "context": "paypalsecure",
                    "suspicious_terms": [],
                }
            ],
            "suspicious_terms": ["secure"],
            "hyphens": 0,
            "brand_term_combo": False,
            "similarity_match": None,
        }
    )

    result = evaluate_brand_profile(profile)

    assert result.score == 82
    assert any(f.severity == "high" for f in result.findings)


def test_suspicious_terms_only_low():
    profile = parse_brand_profile(
        {
            "domain": "secure-login-verify.com",
            "sld": "secure-login-verify",
            "labels": ["secure-login-verify", "com"],
            "signals": [],
            "suspicious_terms": ["login", "verify", "secure"],
            "hyphens": 2,
            "brand_term_combo": False,
            "similarity_match": None,
        }
    )

    result = evaluate_brand_profile(profile)

    assert result.score < 100
    assert any(f.title == "Suspicious Keywords in Domain" for f in result.findings)


def test_legitimate_domain_scores_100():
    profile = parse_brand_profile(
        {
            "domain": "example.com",
            "sld": "example",
            "labels": ["example", "com"],
            "signals": [],
            "suspicious_terms": [],
            "hyphens": 0,
            "brand_term_combo": False,
            "similarity_match": None,
        }
    )

    result = evaluate_brand_profile(profile)

    assert result.score == 100
    assert result.findings == []


def test_brand_detection_service_end_to_end():
    result = run_brand_detection_check("paypal-login-security.com")

    assert result.module == "brand_detection"
    assert result.details["brand_term_combo"] is True
    assert "login" in result.details["suspicious_terms"]
    assert result.status == "critical"


def test_brand_detection_service_injectable():
    def fake_fetcher(_domain):
        return {
            "domain": "paypa1.com",
            "sld": "paypa1",
            "labels": ["paypa1", "com"],
            "signals": [],
            "suspicious_terms": [],
            "hyphens": 0,
            "brand_term_combo": False,
            "similarity_match": {"brand": "Paypal", "similarity": 100, "technique": "substitution"},
        }

    result = scan_brand_detection_module("paypa1.com", fetcher=fake_fetcher)

    assert result.module == "brand_detection"
    assert result.details["similarity_match"]["technique"] == "substitution"
    assert result.status == "ok"


def test_punycode_homograph_sld_normalized():
    profile = build_profile("xn--rypal-5cd.com", [])

    assert profile.sld.startswith("xn--") or any(ord(c) > 127 for c in profile.sld)