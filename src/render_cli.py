import json
from datetime import date
from pathlib import Path
from src.config import DOCS_DIR
from src.db import (
    rebuild_from_jsonl, get_all_advisories, get_recent_dates,
    get_advisories_for_date, get_stats,
)
from src.render import (
    render_readme, render_html_index, render_daily_patch,
    render_silent_page, render_threats_page,
)


def generate_badge(stats: dict):
    DOCS_DIR.mkdir(parents=True, exist_ok=True)

    (DOCS_DIR / "badge-advisories.json").write_text(
        json.dumps({"schemaVersion": 1, "label": "advisories", "message": str(stats["total_advisories"]), "color": "blue"}),
        encoding="utf-8",
    )
    (DOCS_DIR / "badge-patterns.json").write_text(
        json.dumps({"schemaVersion": 1, "label": "patterns", "message": str(stats["total_patterns"]), "color": "purple"}),
        encoding="utf-8",
    )
    print("  Generated badge endpoints")


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

    render_silent_page()
    print("  Rendered docs/silent.html")

    render_threats_page()
    print("  Rendered docs/threats.html")

    generate_badge(stats)

    print("Render complete")


if __name__ == "__main__":
    run()
