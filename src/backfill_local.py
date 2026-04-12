import json
import sys
import time
import requests
from datetime import datetime, timedelta, timezone
from src.config import (
    RATE_LIMIT_DELAY, MAX_DIFF_LINES,
    LLM_SYSTEM_PROMPT, LLM_USER_PROMPT_TEMPLATE,
    TAXONOMY_PATH, STATE_PATH,
)
from src.fetch import fetch_advisories, fetch_commit_diff
from src.diff_filter import filter_diff
from src.analyze import load_taxonomy, _parse_llm_response, _ecosystem_to_language
from src.db import (
    rebuild_from_jsonl, advisory_exists,
    insert_analysis, export_to_jsonl, get_stats,
)
from src.render import render_readme, render_html_index, render_daily_patch
from src.db import get_advisories_for_date, get_recent_dates


OLLAMA_URL = "http://localhost:11434/api/generate"
OLLAMA_MODEL = "qwen2.5-coder:7b"


def call_ollama(user_prompt: str) -> str | None:
    payload = {
        "model": OLLAMA_MODEL,
        "system": LLM_SYSTEM_PROMPT,
        "prompt": user_prompt,
        "stream": False,
        "format": "json",
        "options": {
            "temperature": 0.2,
            "num_predict": 512,
            "num_ctx": 4096,
        },
    }

    try:
        response = requests.post(OLLAMA_URL, json=payload, timeout=300)
        response.raise_for_status()
        data = response.json()
        return data.get("response", "")
    except requests.RequestException as exc:
        print(f"    Ollama error: {exc}")
        return None


def analyze_with_ollama(advisory: dict, filtered_diff: str) -> dict | None:
    taxonomy_ids = load_taxonomy()
    taxonomy_list = ", ".join(taxonomy_ids)

    user_prompt = LLM_USER_PROMPT_TEMPLATE.format(
        ghsa_id=advisory["ghsa_id"],
        severity=advisory["severity"],
        cvss_score=advisory["cvss_score"],
        summary=advisory["summary"],
        package_name=advisory["package_name"],
        ecosystem=advisory["ecosystem"],
        diff_content=filtered_diff[:2000],
        taxonomy_list=taxonomy_list,
    )

    raw_response = call_ollama(user_prompt)
    if not raw_response:
        print(f"    Ollama returned nothing")
        return None

    parsed = _parse_llm_response(raw_response)
    if not parsed:
        print(f"    Parse failed: {raw_response[:200]}")
        return None

    if parsed.get("pattern_id") not in taxonomy_ids:
        parsed["pattern_id"] = "UNCLASSIFIED"

    def _str(val):
        if isinstance(val, dict):
            return json.dumps(val)
        if isinstance(val, list):
            return json.dumps(val)
        return str(val) if val else ""

    return {
        "ghsa_id": advisory["ghsa_id"],
        "date": advisory["published_at"][:10],
        "cve_id": "",
        "repo": advisory["repo"],
        "language": _ecosystem_to_language(advisory["ecosystem"]),
        "severity": advisory["severity"],
        "cvss_score": advisory["cvss_score"],
        "package_name": advisory["package_name"],
        "pattern_id": parsed["pattern_id"],
        "vuln_type": _str(parsed.get("vuln_type", "")),
        "root_cause": _str(parsed.get("root_cause", "")),
        "impact": _str(parsed.get("impact", "")),
        "fix_summary": _str(parsed.get("fix_summary", "")),
        "key_diff": _str(parsed.get("key_diff", "")),
        "confidence": _str(parsed.get("confidence", "LOW")),
        "commit_url": advisory["commit_url"],
    }


def backfill_local(days: int):
    print(f"=== OSDC Local Backfill ({OLLAMA_MODEL} via Ollama) ===")
    print()

    try:
        r = requests.get("http://localhost:11434/api/tags", timeout=5)
        models = [m["name"] for m in r.json().get("models", [])]
        if not any(OLLAMA_MODEL.split(":")[0] in m for m in models):
            print(f"Model {OLLAMA_MODEL} not found. Available: {models}")
            print(f"Run: ollama pull {OLLAMA_MODEL}")
            return
        print(f"Ollama OK, model {OLLAMA_MODEL} available")
    except requests.RequestException:
        print("Cannot connect to Ollama at localhost:11434")
        print("Run: ollama serve")
        return

    print("Warming up model...")
    requests.post(OLLAMA_URL, json={
        "model": OLLAMA_MODEL,
        "prompt": "Say OK",
        "stream": False,
    }, timeout=300)
    print("Model loaded")

    rebuild_from_jsonl()
    stats = get_stats()
    print(f"DB before: {stats['total_advisories']} advisories, {stats['total_patterns']} patterns")

    end = datetime.now(timezone.utc)
    start = end - timedelta(days=days)

    print(f"Fetching advisories from {start.date()} to {end.date()}...")
    advisories = fetch_advisories(start.isoformat())
    print(f"Found {len(advisories)} advisories with patch commits")

    new_advisories = [a for a in advisories if not advisory_exists(a["ghsa_id"])]
    print(f"New (not in DB): {len(new_advisories)}")

    if not new_advisories:
        print("Nothing to backfill")
        return

    processed = 0
    errors = 0
    new_patterns = 0

    for i, advisory in enumerate(new_advisories):
        print(f"  [{i+1}/{len(new_advisories)}] {advisory['ghsa_id']} ({advisory['severity']})...")

        raw_diff = fetch_commit_diff(advisory["commit_url"])
        if not raw_diff:
            print(f"    SKIP: no diff")
            errors += 1
            continue

        filtered = filter_diff(raw_diff)
        if not filtered:
            print(f"    SKIP: no relevant files")
            continue

        result = analyze_with_ollama(advisory, filtered)
        if not result:
            errors += 1
            continue

        pattern_match = insert_analysis(result)
        processed += 1

        if pattern_match["is_new"]:
            new_patterns += 1
            label = "NEW PATTERN"
        else:
            label = f"{pattern_match['occurrences']}x seen"

        print(f"    OK → {result['pattern_id']} [{label}]")

        if processed % 10 == 0:
            export_to_jsonl()
            print(f"    [checkpoint: {processed} saved]")

    export_to_jsonl()

    recent_dates = get_recent_dates(30)
    for d in recent_dates:
        advs = get_advisories_for_date(d)
        if advs:
            render_daily_patch(d, advs)

    render_readme()
    render_html_index()

    stats = get_stats()
    print(f"\n=== Summary ===")
    print(f"Processed: {processed}")
    print(f"New patterns: {new_patterns}")
    print(f"Errors: {errors}")
    print(f"Total DB: {stats['total_advisories']} advisories, {stats['total_patterns']} patterns")
    print(f"\nCommit and push:")
    print(f"  git add -A && git commit -m 'feat: local backfill — {processed} advisories' && git push")


if __name__ == "__main__":
    days = int(sys.argv[1]) if len(sys.argv) > 1 else 7
    backfill_local(days)
