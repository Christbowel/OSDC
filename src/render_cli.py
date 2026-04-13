import json
from datetime import date
from pathlib import Path
from src.config import DOCS_DIR
from src.db import (
    rebuild_from_jsonl, get_all_advisories, get_recent_dates,
    get_advisories_for_date, get_stats,
)
from src.render import render_readme, render_html_index, render_daily_patch


def generate_badge(stats: dict):
    DOCS_DIR.mkdir(parents=True, exist_ok=True)

    badge_advisories = {
        "schemaVersion": 1,
        "label": "advisories",
        "message": str(stats["total_advisories"]),
        "color": "blue",
    }

    badge_patterns = {
        "schemaVersion": 1,
        "label": "patterns",
        "message": str(stats["total_patterns"]),
        "color": "purple",
    }

    (DOCS_DIR / "badge-advisories.json").write_text(
        json.dumps(badge_advisories), encoding="utf-8"
    )
    (DOCS_DIR / "badge-patterns.json").write_text(
        json.dumps(badge_patterns), encoding="utf-8"
    )
    print(f"  Generated badge endpoints")


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

    generate_badge(stats)

    print("Render complete")


if __name__ == "__main__":
    run()
