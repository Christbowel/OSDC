import json
import re
from datetime import date
from jinja2 import Environment, FileSystemLoader
from src.config import (
    TEMPLATES_DIR, PATCHES_DIR, DOCS_DIR, ROOT_DIR,
    DATA_DIR,
)
from src.db import (
    get_pattern_info,
    get_all_advisories, get_stats,
)


SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MODERATE": 2, "MEDIUM": 2, "LOW": 3}


def init_renderer() -> Environment:
    return Environment(
        loader=FileSystemLoader(str(TEMPLATES_DIR)),
        trim_blocks=True,
        lstrip_blocks=True,
    )


def _clean_diff(raw: str) -> str:
    if not raw:
        return ""
    cleaned = raw.strip()
    if cleaned.startswith("{") and "before" in cleaned:
        try:
            obj = json.loads(cleaned)
            before = obj.get("before", "")
            after = obj.get("after", "")
            return f"- {before}\n+ {after}" if before or after else ""
        except json.JSONDecodeError:
            pass
    cleaned = re.sub(r'^```\w*\n?', '', cleaned)
    cleaned = re.sub(r'\n?```$', '', cleaned)
    cleaned = cleaned.strip()
    return cleaned


def _clean_text(raw: str) -> str:
    if not raw:
        return ""
    if isinstance(raw, dict):
        return json.dumps(raw)
    if isinstance(raw, list):
        return json.dumps(raw)
    return str(raw).strip()


def _enrich_advisory(adv: dict) -> dict:
    """Clean text fields and attach pattern info."""
    pattern_info = get_pattern_info(adv["pattern_id"])
    adv["pattern_info"] = pattern_info
    adv["occurrences"] = pattern_info["occurrences"] if pattern_info else 1
    adv["key_diff"] = _clean_diff(adv.get("key_diff", ""))
    adv["root_cause"] = _clean_text(adv.get("root_cause", ""))
    adv["impact"] = _clean_text(adv.get("impact", ""))
    adv["fix_summary"] = _clean_text(adv.get("fix_summary", ""))
    adv["commit_url"] = adv.get("commit_url", "")
    return adv


def render_daily_patch(target_date: str, advisories: list[dict]):
    PATCHES_DIR.mkdir(parents=True, exist_ok=True)
    env = init_renderer()
    template = env.get_template("patch.md.j2")

    enriched = [_enrich_advisory({**adv}) for adv in advisories]

    content = template.render(
        date=target_date,
        advisories=enriched,
        total=len(enriched),
    )

    output_path = PATCHES_DIR / f"{target_date}.md"
    output_path.write_text(content, encoding="utf-8")


def render_readme():
    env = init_renderer()
    template = env.get_template("readme.md.j2")

    all_advisories = get_all_advisories()
    top_advisories = sorted(
        all_advisories,
        key=lambda a: (SEVERITY_ORDER.get(a["severity"], 99), -a["cvss_score"])
    )[:50]

    for adv in top_advisories:
        _enrich_advisory(adv)

    stats = get_stats()

    content = template.render(
        top_advisories=top_advisories,
        stats=stats,
        today=date.today().isoformat(),
    )

    output_path = ROOT_DIR / "README.md"
    output_path.write_text(content, encoding="utf-8")


def render_html_index():
    DOCS_DIR.mkdir(parents=True, exist_ok=True)
    env = init_renderer()
    template = env.get_template("index.html.j2")

    all_advisories = get_all_advisories()

    for adv in all_advisories:
        _enrich_advisory(adv)

    stats = get_stats()

    content = template.render(
        advisories=all_advisories,
        stats=stats,
        today=date.today().isoformat(),
    )

    output_path = DOCS_DIR / "index.html"
    output_path.write_text(content, encoding="utf-8")

    _generate_search_index(all_advisories)


def render_silent_page():
    DOCS_DIR.mkdir(parents=True, exist_ok=True)
    env = init_renderer()
    template = env.get_template("silent.html.j2")

    results_path = DATA_DIR / "silent_results.jsonl"
    suspects = []
    if results_path.exists():
        with open(results_path, "r") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                suspects.append(json.loads(line))

    suspects.sort(key=lambda s: s.get("combined_score", 0), reverse=True)

    state_path = DATA_DIR / "silent_state.json"
    stats = {"last_scan_at": "", "total_scanned": 0, "total_suspects": 0, "watchlist_count": 0}
    if state_path.exists():
        with open(state_path, "r") as f:
            stats.update(json.load(f))

    watchlist_path = DATA_DIR / "watchlist.json"
    if watchlist_path.exists():
        with open(watchlist_path, "r") as f:
            wl = json.load(f)
            stats["watchlist_count"] = len(wl.get("repos", []))

    content = template.render(
        suspects=suspects,
        stats=stats,
        today=date.today().isoformat(),
    )

    output_path = DOCS_DIR / "silent.html"
    output_path.write_text(content, encoding="utf-8")


def _generate_search_index(advisories: list[dict]):
    index = []
    for adv in advisories:
        index.append({
            "id": adv["id"],
            "date": adv["date"],
            "repo": adv["repo"],
            "language": adv["language"],
            "severity": adv["severity"],
            "cvss": adv["cvss_score"],
            "pattern": adv["pattern_id"],
            "vuln_type": adv["vuln_type"],
            "summary": adv.get("root_cause", "")[:200],
            "package": adv.get("package_name", ""),
        })

    output_path = DOCS_DIR / "search-index.json"
    output_path.write_text(
        json.dumps(index, ensure_ascii=False, indent=None),
        encoding="utf-8",
    )


def render_all(target_date: str, analyzed_advisories: list[dict]):
    render_daily_patch(target_date, analyzed_advisories)
    render_readme()
    render_html_index()