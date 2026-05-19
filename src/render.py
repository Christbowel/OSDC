import json
import re
from datetime import date
from pathlib import Path
from functools import lru_cache
from jinja2 import Environment, FileSystemLoader
from src.config import (
    TEMPLATES_DIR, PATCHES_DIR, DOCS_DIR, ROOT_DIR,
    README_DAYS_SHOWN, DATA_DIR,
)
from src.db import (
    get_advisories_for_date, get_pattern_info,
    get_recent_dates, get_all_advisories, get_stats,
)


SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MODERATE": 2, "MEDIUM": 2, "LOW": 3}


def init_renderer() -> Environment:
    return Environment(
        loader=FileSystemLoader(str(TEMPLATES_DIR)),
        trim_blocks=True,
        lstrip_blocks=True,
    )


@lru_cache(maxsize=4096)
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
    return cleaned.strip()


def _clean_text(raw) -> str:
    if not raw:
        return ""
    if isinstance(raw, (dict, list)):
        return json.dumps(raw)
    return str(raw).strip()


def _write_json(name: str, records: list[dict]):
    out_dir = DOCS_DIR / "data"
    out_dir.mkdir(parents=True, exist_ok=True)
    payload = {
        "generated_at": date.today().isoformat(),
        "count": len(records),
        "records": records,
    }
    (out_dir / f"{name}.json").write_text(
        json.dumps(payload, ensure_ascii=False, separators=(",", ":")),
        encoding="utf-8",
    )


def _render_shell(axis: str, axis_title: str, axis_sub: str, out_filename: str):
    env = init_renderer()
    template = env.get_template("app.html.j2")
    html = template.render(axis=axis, axis_title=axis_title, axis_sub=axis_sub)
    (DOCS_DIR / out_filename).write_text(html, encoding="utf-8")


def render_daily_patch(target_date: str, advisories: list[dict]):
    PATCHES_DIR.mkdir(parents=True, exist_ok=True)
    env = init_renderer()
    template = env.get_template("patch.md.j2")

    enriched = []
    for adv in advisories:
        pattern_info = get_pattern_info(adv["pattern_id"])
        enriched.append({
            **adv,
            "pattern_info": pattern_info,
            "key_diff": _clean_diff(adv.get("key_diff", "")),
            "root_cause": _clean_text(adv.get("root_cause", "")),
            "impact": _clean_text(adv.get("impact", "")),
            "fix_summary": _clean_text(adv.get("fix_summary", "")),
        })

    content = template.render(date=target_date, advisories=enriched, total=len(enriched))
    (PATCHES_DIR / f"{target_date}.md").write_text(content, encoding="utf-8")


def render_readme():
    env = init_renderer()
    template = env.get_template("readme.md.j2")

    all_advisories = get_all_advisories()
    top_advisories = sorted(
        all_advisories,
        key=lambda a: (SEVERITY_ORDER.get(a["severity"], 99), -a["cvss_score"])
    )[:50]

    for adv in top_advisories:
        pattern_info = get_pattern_info(adv["pattern_id"])
        adv["occurrences"] = pattern_info["occurrences"] if pattern_info else 1
        adv["root_cause"] = _clean_text(adv.get("root_cause", ""))
        adv["impact"] = _clean_text(adv.get("impact", ""))
        adv["fix_summary"] = _clean_text(adv.get("fix_summary", ""))
        adv["key_diff"] = _clean_diff(adv.get("key_diff", ""))

    content = template.render(
        top_advisories=top_advisories,
        stats=get_stats(),
        today=date.today().isoformat(),
    )
    (ROOT_DIR / "README.md").write_text(content, encoding="utf-8")


def render_html_index():
    DOCS_DIR.mkdir(parents=True, exist_ok=True)
    advisories = get_all_advisories()
    records = []
    for a in advisories:
        records.append({
            "id": a["id"],
            "url": a.get("commit_url", ""),
            "repo": a.get("repo", ""),
            "date": a.get("date", ""),
            "severity": a.get("severity", ""),
            "cvss": a.get("cvss_score", 0),
            "language": a.get("language", ""),
            "pattern": a.get("pattern_id", ""),
            "cve": a.get("cve_id", ""),
            "package": a.get("package_name", ""),
            "summary": (a.get("root_cause") or a.get("fix_summary") or "")[:280],
        })
    _write_json("advisories", records)
    _render_shell(
        "advisories",
        "Advisories",
        "Publicly disclosed vulnerabilities with linked fix commits, analyzed by Gemini.",
        "index.html",
    )


def render_silent_page():
    DOCS_DIR.mkdir(parents=True, exist_ok=True)
    results_path = DATA_DIR / "silent_results.jsonl"
    records = []
    if results_path.exists():
        with open(results_path) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    s = json.loads(line)
                except json.JSONDecodeError:
                    continue
                records.append({
                    "sha": s.get("commit_sha", ""),
                    "url": s.get("commit_url", ""),
                    "repo": s.get("repo", ""),
                    "date": s.get("date", ""),
                    "author": s.get("author", ""),
                    "score": s.get("normalized_score", 0),
                    "msg": (s.get("message") or "")[:240],
                    "fp": s.get("fingerprint_match"),
                    "top_file": s.get("top_file", ""),
                })
    records.sort(key=lambda r: r["score"], reverse=True)
    _write_json("silent", records)
    _render_shell(
        "silent",
        "Silent Patches",
        "Security fixes pushed to high-value repos without a public advisory.",
        "silent.html",
    )


def render_threats_page():
    DOCS_DIR.mkdir(parents=True, exist_ok=True)
    advisories = get_all_advisories()
    records = []
    for a in advisories:
        if a.get("cve_id"):
            continue
        records.append({
            "id": a["id"],
            "url": a.get("commit_url", ""),
            "repo": a.get("repo", ""),
            "date": a.get("date", ""),
            "severity": a.get("severity", ""),
            "cvss": a.get("cvss_score", 0),
            "language": a.get("language", ""),
            "pattern": a.get("pattern_id", ""),
            "package": a.get("package_name", ""),
            "summary": (a.get("root_cause") or a.get("fix_summary") or "")[:280],
        })
    _write_json("threats", records)
    _render_shell(
        "threats",
        "No-CVE Threats",
        "GHSA advisories without an assigned CVE — silent disclosures.",
        "threats.html",
    )


def render_all(target_date: str, analyzed_advisories: list[dict]):
    render_daily_patch(target_date, analyzed_advisories)
    render_readme()
    render_html_index()
    render_silent_page()
    render_threats_page()
