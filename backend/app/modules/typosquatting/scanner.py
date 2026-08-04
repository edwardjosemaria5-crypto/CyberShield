from concurrent.futures import ThreadPoolExecutor
import socket

from app.modules.typosquatting.homoglyphs import find_homoglyphs
from app.modules.typosquatting.keyboard import keyboard_neighbors
from app.modules.typosquatting.levenshtein import levenshtein_distance


def _check_domain_active(candidate: str) -> dict | None:
    try:
        ip = socket.gethostbyname(candidate)
        return {"candidate": candidate, "ip": ip, "is_active": True}
    except Exception:
        return None


def scan_typosquatting_module(domain: str) -> dict:
    """Generate typosquatted domain permutations and detect active squatted domains."""
    target = domain.replace("https://", "").replace("http://", "").split("/")[0].split(":")[0]

    keyboard_candidates = keyboard_neighbors(target)
    homoglyph_candidates = find_homoglyphs(target)
    all_candidates = list(set(keyboard_candidates + homoglyph_candidates))[:12]

    active_squatters = []
    with ThreadPoolExecutor(max_workers=8) as executor:
        futures = [executor.submit(_check_domain_active, c) for c in all_candidates]
        for future in futures:
            res = future.result()
            if res:
                res["distance"] = levenshtein_distance(target, res["candidate"])
                active_squatters.append(res)

    risk = "High" if len(active_squatters) > 2 else "Medium" if len(active_squatters) > 0 else "Low"

    return {
        "domain": target,
        "total_permutations_tested": len(all_candidates),
        "active_squatted_domains": active_squatters,
        "active_count": len(active_squatters),
        "risk_level": risk,
        "recommendation": "Monitor or preemptively register common typosquatting variations." if active_squatters else "No active typosquatting threats detected.",
    }
