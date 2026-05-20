import json
import sys
import time
import requests
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional
from src.config import DATA_DIR, GITHUB_TOKEN
from src.db import rebuild_from_jsonl, get_all_advisories


DIFF_DIR = DATA_DIR / "enrichments" / "diff"
SILENT_PATH = DATA_DIR / "silent_results.jsonl"
MAX_DIFF_SIZE = 30000
MAX_FILE_LINES = 600
RATE_DELAY = 0.12


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _gh_diff(repo: str, sha: str) -> Optional[str]:
    if not repo or not sha:
        return None
    headers = {"Accept": "application/vnd.github.diff", "User-Agent": "OSDC-Enrich/1.0"}
    if GITHUB_TOKEN:
        headers["Authorization"] = f"Bearer {GITHUB_TOKEN}"
    try:
        r = requests.get(
            f"https://api.github.com/repos/{repo}/commits/{sha}",
            headers=headers,
            timeout=30,
        )
        if r.status_code == 200:
            return r.text
        if r.status_code == 403 and r.headers.get("X-RateLimit-Remaining") == "0":
            reset = int(r.headers.get("X-RateLimit-Reset", "0"))
            wait = max(reset - int(time.time()), 5)
            print(f"    GH rate limit, sleeping {wait}s")
            time.sleep(min(wait, 90))
            return _gh_diff(repo, sha)
        return None
    except requests.RequestException:
        return None


def parse_diff(diff_text: str) -> dict:
    if not diff_text:
        return {"files": [], "additions": 0, "deletions": 0, "truncated": False}

    files = []
    current = None
    total_size = 0
    truncated = False
    add_count = 0
    del_count = 0

    for raw_line in diff_text.split("\n"):
        if total_size > MAX_DIFF_SIZE:
            truncated = True
            break

        if raw_line.startswith("diff --git"):
            if current:
                files.append(current)
            parts = raw_line.split()
            path = "unknown"
            for p in parts:
                if p.startswith("b/"):
                    path = p[2:]
                    break
            current = {
                "path": path,
                "lines": [],
                "additions": 0,
                "deletions": 0,
                "truncated": False,
            }
            total_size += len(raw_line) + 1
        elif current is not None:
            if raw_line.startswith("+++") or raw_line.startswith("---") or raw_line.startswith("index ") or raw_line.startswith("new file") or raw_line.startswith("deleted file") or raw_line.startswith("similarity"):
                continue
            if raw_line.startswith("+") and not raw_line.startswith("+++"):
                current["additions"] += 1
                add_count += 1
            elif raw_line.startswith("-") and not raw_line.startswith("---"):
                current["deletions"] += 1
                del_count += 1

            if len(current["lines"]) < MAX_FILE_LINES:
                current["lines"].append(raw_line)
                total_size += len(raw_line) + 1
            else:
                current["truncated"] = True

    if current:
        files.append(current)

    return {
        "files": files,
        "additions": add_count,
        "deletions": del_count,
        "truncated": truncated,
        "file_count": len(files),
    }


def enrich_diff(record_id: str, axis: str, repo: str, sha: str) -> dict:
    diff_text = _gh_diff(repo, sha)
    if not diff_text:
        return {
            "id": record_id,
            "axis": axis,
            "repo": repo,
            "sha": sha,
            "parsed": None,
            "error": "fetch_failed",
            "fetched_at": _now(),
        }

    parsed = parse_diff(diff_text)
    return {
        "id": record_id,
        "axis": axis,
        "repo": repo,
        "sha": sha,
        "parsed": parsed,
        "error": None,
        "fetched_at": _now(),
    }


def load_targets() -> list[dict]:
    rebuild_from_jsonl()
    advisories = get_all_advisories()
    targets = []

    for a in advisories:
        sha = None
        url = a.get("commit_url", "")
        if "/commit/" in url:
            sha = url.rsplit("/commit/", 1)[-1].split("?")[0].split("#")[0]
        if not sha:
            continue
        targets.append({
            "id": a["id"],
            "axis": "advisories",
            "repo": a.get("repo", ""),
            "sha": sha,
        })

    if SILENT_PATH.exists():
        with open(SILENT_PATH) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    s = json.loads(line)
                except json.JSONDecodeError:
                    continue
                sha = s.get("commit_sha", "")
                if not sha:
                    continue
                targets.append({
                    "id": sha,
                    "axis": "silent",
                    "repo": s.get("repo", ""),
                    "sha": sha,
                })

    return targets


def run(limit: Optional[int] = None):
    DIFF_DIR.mkdir(parents=True, exist_ok=True)
    targets = load_targets()
    print(f"=== OSDC Diff Enrichment === ({len(targets)} candidates)")

    new_count = 0
    skipped = 0
    failed = 0
    started_at = time.time()

    for i, t in enumerate(targets, 1):
        record_id = t["id"]
        cache_path = DIFF_DIR / f"{record_id}.json"
        if cache_path.exists():
            try:
                cached = json.loads(cache_path.read_text())
                if cached.get("parsed") is not None:
                    skipped += 1
                    continue
            except json.JSONDecodeError:
                pass

        try:
            enriched = enrich_diff(record_id, t["axis"], t["repo"], t["sha"])
            if enriched.get("parsed") is not None:
                cache_path.write_text(json.dumps(enriched, ensure_ascii=False, separators=(",", ":")))
                new_count += 1
                parsed = enriched["parsed"]
                print(f"  [{i}/{len(targets)}] {record_id[:12]} +{parsed['additions']}/-{parsed['deletions']} ({parsed['file_count']}f)")
            else:
                failed += 1
        except Exception as exc:
            failed += 1
            print(f"  [FAIL] {record_id[:12]}: {exc}")

        time.sleep(RATE_DELAY)

        if limit and new_count >= limit:
            print(f"  [LIMIT {limit} reached]")
            break

    elapsed = time.time() - started_at
    print(f"\n=== Summary ===")
    print(f"New diffs: {new_count}")
    print(f"Skipped (cached): {skipped}")
    print(f"Failed: {failed}")
    print(f"Elapsed: {elapsed:.1f}s")


if __name__ == "__main__":
    limit = None
    if len(sys.argv) > 1:
        try:
            limit = int(sys.argv[1])
        except ValueError:
            pass
    run(limit)
