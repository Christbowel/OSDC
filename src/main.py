import json
import time
import signal
import sys
from datetime import datetime, timezone
from src.config import (
    STATE_PATH, MAX_DAILY_CALLS, RATE_LIMIT_DELAY,
)
from src.fetch import fetch_advisories, fetch_commit_diff
from src.diff_filter import filter_diff
from src.analyze import analyze_advisory
from src.db import (
    rebuild_from_jsonl, advisory_exists, insert_analysis,
    insert_pending, export_to_jsonl, get_advisories_for_date,
    get_stats,
)
from src.render import render_all


_shutdown_requested = False


def _handle_signal(signum, frame):
    global _shutdown_requested
    _shutdown_requested = True
    print(f"\nGraceful shutdown requested (signal {signum}), saving progress...")


def load_state() -> dict:
    if STATE_PATH.exists():
        with open(STATE_PATH, "r") as f:
            return json.load(f)
    return {
        "last_run_at": "2000-01-01T00:00:00Z",
        "pending_ids": [],
        "today_advisory_count": 0,
        "today_run_number": 0,
    }


def save_state(state: dict):
    STATE_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(STATE_PATH, "w") as f:
        json.dump(state, f, indent=2, ensure_ascii=False)


def save_progress(state: dict):
    save_state(state)
    export_to_jsonl()


def run():
    signal.signal(signal.SIGTERM, _handle_signal)
    signal.signal(signal.SIGINT, _handle_signal)

    now = datetime.now(timezone.utc)
    today = now.strftime("%Y-%m-%d")

    print(f"=== OSDC Run {now.isoformat()} ===")

    state = load_state()
    last_run = state["last_run_at"]

    last_run_date = state.get("last_run_at", "")[:10]
    if last_run_date == today:
        run_number = state.get("today_run_number", 0) + 1
        advisory_count = state.get("today_advisory_count", 0)
    else:
        run_number = 1
        advisory_count = 0

    print(f"Run #{run_number} for {today}")
    print(f"Fetching advisories since {last_run}")

    rebuild_from_jsonl()

    advisories = fetch_advisories(last_run)
    print(f"Found {len(advisories)} advisories with patch commits")

    new_advisories = [
        a for a in advisories if not advisory_exists(a["ghsa_id"])
    ]
    print(f"New (not yet processed): {len(new_advisories)}")

    calls_remaining = MAX_DAILY_CALLS - advisory_count
    analyzed = []
    new_patterns = 0
    errors = 0

    for i, advisory in enumerate(new_advisories):
        if _shutdown_requested:
            print(f"Shutdown: saving {len(analyzed)} analyzed so far")
            break

        if calls_remaining <= 0:
            insert_pending(advisory["ghsa_id"], advisory)
            continue

        print(f"  [{i+1}/{len(new_advisories)}] {advisory['ghsa_id']} ({advisory['severity']})...")

        raw_diff = fetch_commit_diff(advisory["commit_url"])
        if not raw_diff:
            print(f"    SKIP: no diff available")
            errors += 1
            continue

        filtered = filter_diff(raw_diff)
        if not filtered:
            print(f"    SKIP: no relevant files in diff")
            continue

        result = analyze_advisory(advisory, filtered)
        if not result:
            print(f"    ERROR: LLM analysis failed")
            errors += 1
            continue

        pattern_match = insert_analysis(result)
        analyzed.append(result)

        if pattern_match["is_new"]:
            new_patterns += 1
            label = "NEW PATTERN"
        else:
            label = f"{pattern_match['occurrences']}x seen"

        print(f"    OK → {result['pattern_id']} [{label}]")

        calls_remaining -= 1
        advisory_count += 1

        if len(analyzed) % 5 == 0:
            save_progress({
                "last_run_at": now.isoformat(),
                "pending_ids": [],
                "today_advisory_count": advisory_count,
                "today_run_number": run_number,
            })
            print(f"    [checkpoint: {len(analyzed)} saved]")

        time.sleep(RATE_LIMIT_DELAY)

    export_to_jsonl()

    all_today = get_advisories_for_date(today)
    if all_today:
        render_all(today, all_today)

    state = {
        "last_run_at": now.isoformat(),
        "pending_ids": [],
        "today_advisory_count": advisory_count,
        "today_run_number": run_number,
    }
    save_state(state)

    stats = get_stats()
    run_log = {
        "run_at": now.isoformat(),
        "run_number": run_number,
        "fetched": len(advisories),
        "new": len(new_advisories),
        "analyzed": len(analyzed),
        "new_patterns": new_patterns,
        "errors": errors,
        "pending": stats["pending_count"],
        "total_advisories": stats["total_advisories"],
        "total_patterns": stats["total_patterns"],
    }

    log_path = STATE_PATH.parent / "run_log.json"
    log_path.write_text(
        json.dumps(run_log, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )

    print(f"\n=== Summary ===")
    print(f"Analyzed: {len(analyzed)}")
    print(f"New patterns: {new_patterns}")
    print(f"Errors: {errors}")
    print(f"Total DB: {stats['total_advisories']} advisories, {stats['total_patterns']} patterns")

    return len(analyzed)


if __name__ == "__main__":
    run()
