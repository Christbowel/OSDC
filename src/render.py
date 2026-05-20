import json
import re
import shutil
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

ENRICH_REACH_DIR = DATA_DIR / "enrichments" / "reach"
DOCS_ENRICH_DIR = DOCS_DIR / "data" / "enrichments"


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


def _load_reach_index() -> dict:
    index = {}
    if not ENRICH_REACH_DIR.exists():
        return index
    for p in ENRICH_REACH_DIR.iterdir():
        if not p.suffix == ".json":
            continue
        try:
            data = json.loads(p.read_text())
            rid = data.get("id")
            if rid:
                index[rid] = data
        except json.JSONDecodeError:
            continue
    return index


def _summarize_reach(reach: dict) -> dict:
    if not reach:
        return {}
    br = reach.get("blast_radius") or {}
    dl = reach.get("downloads") or {}
    dp = reach.get("dependents") or {}
    pkg = reach.get("package") or {}
    return {
        "tier": br.get("tier", "UNKNOWN"),
        "score": br.get("score", 0),
        "dl_weekly": dl.get("weekly", 0),
        "dep_direct": dp.get("direct", 0),
        "dep_indirect": dp.get("indirect", 0),
        "pkg_name": pkg.get("name"),
        "pkg_eco": pkg.get("ecosystem"),
    }


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


def _render_shell(template_name: str, out_filename: str, **context):
    env = init_renderer()
    template = env.get_template(template_name)
    html = template.render(**context)
    (DOCS_DIR / out_filename).write_text(html, encoding="utf-8")


def _copy_enrichments_to_docs():
    src = DATA_DIR / "enrichments"
    if not src.exists():
        return
    DOCS_ENRICH_DIR.mkdir(parents=True, exist_ok=True)
    for sub in ("reach", "diff"):
        sub_src = src / sub
        if sub_src.exists():
            sub_dst = DOCS_ENRICH_DIR / sub
            if sub_dst.exists():
                shutil.rmtree(sub_dst)
            shutil.copytree(sub_src, sub_dst)


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
    reach_index = _load_reach_index()

    records = []
    for a in advisories:
        rec = {
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
            "cwe": a.get("cwe_id", ""),
            "vuln_type": a.get("vuln_type", ""),
            "confidence": a.get("confidence", ""),
            "root_cause": _clean_text(a.get("root_cause", "")),
            "impact": _clean_text(a.get("impact", "")),
            "fix_summary": _clean_text(a.get("fix_summary", "")),
            "key_diff": _clean_diff(a.get("key_diff", "")),
            "summary": (a.get("root_cause") or a.get("fix_summary") or "")[:280],
        }
        if a["id"] in reach_index:
            rec["reach"] = _summarize_reach(reach_index[a["id"]])
        records.append(rec)
    _write_json("advisories", records)
    _render_shell(
        "app.html.j2",
        "index.html",
        axis="advisories",
        axis_title="Advisories",
        axis_sub="Publicly disclosed vulnerabilities with linked fix commits, analyzed by Gemini.",
    )


def render_silent_page():
    DOCS_DIR.mkdir(parents=True, exist_ok=True)
    results_path = DATA_DIR / "silent_results.jsonl"
    reach_index = _load_reach_index()
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
                rec = {
                    "sha": s.get("commit_sha", ""),
                    "url": s.get("commit_url", ""),
                    "repo": s.get("repo", ""),
                    "date": s.get("date", ""),
                    "author": s.get("author", ""),
                    "score": s.get("normalized_score", 0),
                    "heuristic_score": s.get("heuristic_score", 0),
                    "msg": (s.get("message") or "")[:240],
                    "fp": s.get("fingerprint_match"),
                    "fp_score": s.get("fingerprint_score", 0),
                    "fp_tokens": s.get("fingerprint_matched_tokens") or [],
                    "top_file": s.get("top_file", ""),
                    "top_file_score": s.get("top_file_score", 0),
                    "signals": s.get("top_file_signals") or [],
                    "files_changed": s.get("files_changed", 0),
                }
                if s.get("commit_sha") in reach_index:
                    rec["reach"] = _summarize_reach(reach_index[s["commit_sha"]])
                records.append(rec)

    records.sort(key=lambda r: r["score"], reverse=True)
    _write_json("silent", records)
    _render_shell(
        "app.html.j2",
        "silent.html",
        axis="silent",
        axis_title="Silent Patches",
        axis_sub="Security fixes pushed to high-value repos without a public advisory.",
    )


def render_threats_page():
    DOCS_DIR.mkdir(parents=True, exist_ok=True)
    advisories = get_all_advisories()
    reach_index = _load_reach_index()
    records = []

    for a in advisories:
        if a.get("cve_id"):
            continue
        rec = {
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
        }
        if a["id"] in reach_index:
            rec["reach"] = _summarize_reach(reach_index[a["id"]])
        records.append(rec)

    _write_json("threats", records)
    _render_shell(
        "app.html.j2",
        "threats.html",
        axis="threats",
        axis_title="No-CVE Threats",
        axis_sub="GHSA advisories without an assigned CVE — silent disclosures.",
    )


def render_detail_shell():
    DOCS_DIR.mkdir(parents=True, exist_ok=True)
    _render_shell("detail.html.j2", "detail.html")


def render_all(target_date: str, analyzed_advisories: list[dict]):
    render_daily_patch(target_date, analyzed_advisories)
    render_readme()
    _copy_enrichments_to_docs()
    render_html_index()
    render_silent_page()
    render_threats_page()
    render_detail_shell()
