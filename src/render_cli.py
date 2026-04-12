from datetime import date
from src.db import (
    rebuild_from_jsonl, get_all_advisories, get_recent_dates,
    get_advisories_for_date, get_stats,
)
from src.render import render_readme, render_html_index, render_daily_patch


def run():
    print("Rebuilding DB from JSONL...")
    rebuild_from_jsonl()

    stats = get_stats()
    print(f"DB: {stats['total_advisories']} advisories, {stats['total_patterns']} patterns")

    if stats["total_advisories"] == 0:
        print("No advisories in DB, skipping render")
        return

    recent_dates = get_recent_dates(30)
    for d in recent_dates:
        advisories = get_advisories_for_date(d)
        if advisories:
            render_daily_patch(d, advisories)
            print(f"  Rendered patches/{d}.md ({len(advisories)} advisories)")

    render_readme()
    print("  Rendered README.md")

    render_html_index()
    print("  Rendered docs/index.html + search-index.json")

    print("Render complete")


if __name__ == "__main__":
    run()
