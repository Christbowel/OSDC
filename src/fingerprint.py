import json
import re
from src.config import DATA_DIR


_fingerprints_cache = None


def load_fingerprints() -> dict:
    global _fingerprints_cache
    if _fingerprints_cache is not None:
        return _fingerprints_cache

    fp_path = DATA_DIR / "fingerprints.json"
    if not fp_path.exists():
        _fingerprints_cache = {}
        return _fingerprints_cache

    with open(fp_path, "r") as f:
        _fingerprints_cache = json.load(f)

    return _fingerprints_cache


def tokenize_diff(patch_text: str) -> tuple[set, set]:
    add_tokens = set()
    del_tokens = set()

    for line in patch_text.splitlines():
        if line.startswith("+") and not line.startswith("+++"):
            tokens = _extract_tokens(line[1:])
            add_tokens.update(tokens)
        elif line.startswith("-") and not line.startswith("---"):
            tokens = _extract_tokens(line[1:])
            del_tokens.update(tokens)

    return add_tokens, del_tokens


def _extract_tokens(line: str) -> set:
    tokens = set()
    identifiers = re.findall(r'[a-zA-Z_][a-zA-Z0-9_]*(?:\.[a-zA-Z_][a-zA-Z0-9_]*)*', line)
    for ident in identifiers:
        tokens.add(ident.lower())
        parts = ident.split(".")
        for part in parts:
            tokens.add(part.lower())
            sub_parts = re.findall(r'[a-z]+|[A-Z][a-z]*|[A-Z]+(?=[A-Z][a-z]|\b)', part)
            for sp in sub_parts:
                if len(sp) > 2:
                    tokens.add(sp.lower())

    return tokens


def jaccard_similarity(set_a: set, set_b: set) -> float:
    if not set_a or not set_b:
        return 0.0
    intersection = set_a & set_b
    union = set_a | set_b
    return len(intersection) / len(union)


def match_fingerprints(patch_text: str) -> list[dict]:
    fingerprints = load_fingerprints()
    if not fingerprints:
        return []

    add_tokens, del_tokens = tokenize_diff(patch_text)
    all_tokens = add_tokens | del_tokens

    if not all_tokens:
        return []

    matches = []

    for pattern_id, fp in fingerprints.items():
        fp_add = set(fp.get("add_tokens", []))
        fp_del = set(fp.get("del_tokens", []))
        fp_all = fp_add | fp_del

        if not fp_all:
            continue

        add_sim = jaccard_similarity(add_tokens, fp_add) if fp_add else 0.0
        del_sim = jaccard_similarity(del_tokens, fp_del) if fp_del else 0.0
        overall_sim = jaccard_similarity(all_tokens, fp_all)

        weighted_score = (add_sim * 0.4) + (del_sim * 0.3) + (overall_sim * 0.3)

        if weighted_score < 0.05:
            continue

        matched_add = sorted(add_tokens & fp_add)[:10]
        matched_del = sorted(del_tokens & fp_del)[:10]

        matches.append({
            "pattern_id": pattern_id,
            "pattern_name": fp.get("name", pattern_id),
            "score": round(weighted_score, 4),
            "add_similarity": round(add_sim, 4),
            "del_similarity": round(del_sim, 4),
            "overall_similarity": round(overall_sim, 4),
            "matched_add_tokens": matched_add,
            "matched_del_tokens": matched_del,
            "sample_count": fp.get("sample_count", 0),
        })

    matches.sort(key=lambda m: m["score"], reverse=True)
    return matches[:5]


def get_best_match(patch_text: str) -> dict | None:
    matches = match_fingerprints(patch_text)
    if matches and matches[0]["score"] >= 0.1:
        return matches[0]
    return None


def score_with_fingerprints(
    heuristic_result: dict, files: list[dict]
) -> tuple[float, dict | None, float]:
    """Combine heuristic score with fingerprint matching.

    Returns (normalized_score, best_fingerprint, fp_score).
    """
    combined_patch = "\n".join(
        f.get("patch", "") for f in files if f.get("patch")
    )
    fingerprint_matches = match_fingerprints(combined_patch)

    best_fp = fingerprint_matches[0] if fingerprint_matches else None
    fp_score = best_fp["score"] if best_fp else 0.0

    normalized = heuristic_result["normalized_score"]
    if best_fp:
        normalized = min(normalized + (fp_score * 30), 100)

    return normalized, best_fp, fp_score