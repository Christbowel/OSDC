import sys
import time
from datetime import datetime, timedelta, timezone
from src.config import RATE_LIMIT_DELAY, MAX_DAILY_CALLS
from src.fetch import fetch_advisories, fetch_commit_diff
from src.diff_filter import filter_diff
from src.analyze import analyze_advisory
from src.db import (
    rebuild_from_jsonl, advisory_exists,
    insert_analysis, export_to_jsonl,
)
from src.render import render_all


def backfill(days: int):
    rebuild_from_jsonl()

    end = datetime.now(timezone.utc)
    start = end - timedelta(days=days)

    print(f"Backfill: fetching advisories from {start.isoformat()} to {end.isoformat()}")

    advisories = fetch_advisories(start.isoformat())
    print(f"Found {len(advisories)} advisories with patch commits")

    processed = 0
    skipped = 0

    for advisory in advisories:
        if processed >= MAX_DAILY_CALLS * days:
            print(f"Backfill limit reached ({processed} processed)")
            break

        if advisory_exists(advisory["ghsa_id"]):
            skipped += 1
            continue

        raw_diff = fetch_commit_diff(advisory["commit_url"])
        if not raw_diff:
            continue

        filtered = filter_diff(raw_diff)
        if not filtered:
            continue

        result = analyze_advisory(advisory, filtered)
        if not result:
            continue

        insert_analysis(result)
        processed += 1
        print(f"  [{processed}] {advisory['ghsa_id']} → {result['pattern_id']}")
        time.sleep(RATE_LIMIT_DELAY)

    export_to_jsonl()

    if processed > 0:
        today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        from src.db import get_advisories_for_date
        advisories_today = get_advisories_for_date(today)
        if advisories_today:
            render_all(today, advisories_today)

    print(f"Backfill complete: {processed} analyzed, {skipped} skipped")


if __name__ == "__main__":
    days = int(sys.argv[1]) if len(sys.argv) > 1 else 7
    backfill(days)
