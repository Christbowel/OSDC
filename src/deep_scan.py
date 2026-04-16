import json
import sys
import time
import os
import requests
from datetime import datetime, timezone
from src.config import DATA_DIR
from src.heuristics import score_commit
from src.fingerprint import match_fingerprints


GITHUB_API = "https://api.github.com"
GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN", "")
REQUEST_DELAY = 0.8
RESULTS_DIR = DATA_DIR / "deep_scans"


def github_get(url: str, params: dict = None) -> dict | list | None:
    headers = {"Accept": "application/vnd.github.v3+json"}
    if GITHUB_TOKEN:
        headers["Authorization"] = f"Bearer {GITHUB_TOKEN}"

    full_url = f"{GITHUB_API}{url}" if url.startswith("/") else url

    try:
        response = requests.get(full_url, headers=headers, params=params, timeout=30)
        if response.status_code == 403:
            remaining = response.headers.get("X-RateLimit-Remaining", "?")
            reset = response.headers.get("X-RateLimit-Reset", "?")
            print(f"  Rate limited (remaining: {remaining}, reset: {reset})")
            if remaining == "0":
                wait = max(int(reset) - int(time.time()), 10)
                print(f"  Waiting {wait}s for rate limit reset...")
                time.sleep(wait)
                return github_get(url, params)
            return None
        if response.status_code == 404:
            return None
        response.raise_for_status()
        return response.json()
    except requests.RequestException as exc:
        print(f"  API error: {exc}")
        return None


def get_link_next(response_headers: dict) -> str | None:
    link = response_headers.get("Link", "")
    for part in link.split(","):
        if 'rel="next"' in part:
            url = part.split(";")[0].strip().strip("<>")
            return url
    return None


def fetch_all_commits(repo: str, since: str = None, until: str = None, per_page: int = 100) -> list[dict]:
    all_commits = []
    params = {"per_page": per_page}
    if since:
        params["since"] = since
    if until:
        params["until"] = until

    url = f"/repos/{repo}/commits"
    use_params = True

    page = 0
    while url:
        page += 1
        headers = {"Accept": "application/vnd.github.v3+json"}
        if GITHUB_TOKEN:
            headers["Authorization"] = f"Bearer {GITHUB_TOKEN}"

        full_url = f"{GITHUB_API}{url}" if url.startswith("/") else url
        try:
            response = requests.get(full_url, headers=headers, params=params if use_params else None, timeout=30)
            if response.status_code == 403:
                remaining = response.headers.get("X-RateLimit-Remaining", "0")
                if remaining == "0":
                    reset = int(response.headers.get("X-RateLimit-Reset", "0"))
                    wait = max(reset - int(time.time()), 10)
                    print(f"  Rate limited, waiting {wait}s...")
                    time.sleep(wait)
                    continue
                return all_commits
            response.raise_for_status()
            commits = response.json()
            if not commits:
                break
            all_commits.extend(commits)
            print(f"  Page {page}: {len(commits)} commits (total: {len(all_commits)})", end="\r", flush=True)

            next_url = get_link_next(dict(response.headers))
            url = next_url
            use_params = False
            time.sleep(REQUEST_DELAY)
        except requests.RequestException as exc:
            print(f"  Error on page {page}: {exc}")
            break

    print()
    return all_commits


def deep_scan(repo: str, since: str = None, until: str = None, max_commits: int = 5000):
    now = datetime.now(timezone.utc)
    safe_repo = repo.replace("/", "_")

    print(f"=== OSDC Deep Scan: {repo} ===")
    print(f"Since: {since or 'beginning'}")
    print(f"Until: {until or 'now'}")
    print()

    print("Fetching commit history...")
    commits = fetch_all_commits(repo, since=since, until=until)
    print(f"Total commits: {len(commits)}")

    if len(commits) > max_commits:
        print(f"Limiting to most recent {max_commits} commits")
        commits = commits[:max_commits]

    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    results_path = RESULTS_DIR / f"{safe_repo}.jsonl"

    seen = set()
    if results_path.exists():
        with open(results_path, "r") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    record = json.loads(line)
                except json.JSONDecodeError:
                    continue
                seen.add(record.get("commit_sha", ""))
        print(f"Already scanned: {len(seen)} commits")

    new_commits = [c for c in commits if c.get("sha", "") not in seen]
    print(f"New to scan: {len(new_commits)}")

    if not new_commits:
        print("Nothing new to scan")
        return

    suspects = []
    skipped = 0
    errors = 0

    for i, commit in enumerate(new_commits):
        sha = commit.get("sha", "")
        message = commit.get("commit", {}).get("message", "").split("\n")[0]

        if (i + 1) % 50 == 0 or (i + 1) == len(new_commits):
            print(f"  [{i+1}/{len(new_commits)}] {len(suspects)} suspects so far...", flush=True)

        detail = github_get(f"/repos/{repo}/commits/{sha}")
        if not detail:
            errors += 1
            time.sleep(REQUEST_DELAY)
            continue

        files = detail.get("files", [])
        if not files:
            skipped += 1
            continue

        heuristic_result = score_commit(message, files)

        if not heuristic_result["threshold_met"]:
            skipped += 1
            time.sleep(REQUEST_DELAY)
            continue

        combined_patch = "\n".join(f.get("patch", "") for f in files if f.get("patch"))
        fingerprint_matches = match_fingerprints(combined_patch)

        best_fp = fingerprint_matches[0] if fingerprint_matches else None
        fp_score = best_fp["score"] if best_fp else 0.0

        normalized = heuristic_result["normalized_score"]
        if best_fp:
            normalized = min(normalized + (fp_score * 30), 100)

        top_file = heuristic_result["files"][0] if heuristic_result["files"] else {}
        author = detail.get("commit", {}).get("author", {})

        result = {
            "commit_sha": sha,
            "repo": repo,
            "commit_url": f"https://github.com/{repo}/commit/{sha}",
            "message": message[:200],
            "date": author.get("date", ""),
            "author": author.get("name", ""),
            "normalized_score": round(normalized, 1),
            "heuristic_score": heuristic_result["score"],
            "heuristic_normalized": heuristic_result["normalized_score"],
            "fingerprint_match": best_fp["pattern_name"] if best_fp else None,
            "fingerprint_score": round(fp_score, 4),
            "top_file": top_file.get("file", ""),
            "top_file_score": top_file.get("score", 0),
            "top_file_signals": top_file.get("signals", []),
            "added_sample": top_file.get("added_sample", "")[:300],
            "removed_sample": top_file.get("removed_sample", "")[:300],
            "files_changed": len(files),
            "scan_date": now.isoformat(),
            "status": "SUSPECT",
        }

        with open(results_path, "a") as f:
            f.write(json.dumps(result, ensure_ascii=False) + "\n")

        suspects.append(result)

        severity = "HIGH" if normalized >= 60 else "MEDIUM" if normalized >= 30 else "LOW"
        print(f"  [{i+1}/{len(new_commits)}] {severity} score={normalized} {sha[:8]} {message[:60]}")

        time.sleep(REQUEST_DELAY)

    print(f"\n=== Deep Scan Summary: {repo} ===")
    print(f"Commits scanned: {len(new_commits) - skipped - errors}")
    print(f"Skipped: {skipped}")
    print(f"Errors: {errors}")
    print(f"Suspects found: {len(suspects)}")

    if suspects:
        print(f"\nResults saved to: {results_path}")
        print("\nTop suspects:")
        top = sorted(suspects, key=lambda s: s["normalized_score"], reverse=True)[:10]
        for s in top:
            print(f"  score={s['normalized_score']:5.1f}  {s['commit_sha'][:8]}  {s['message'][:60]}")
            if s["top_file_signals"]:
                print(f"           signals: {', '.join(s['top_file_signals'][:5])}")

    print(f"\nTo review: open {results_path}")
    print(f"To add to main results: cat {results_path} >> data/silent_results.jsonl")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage:")
        print("  python -m src.deep_scan owner/repo")
        print("  python -m src.deep_scan owner/repo --since 2025-01-01")
        print("  python -m src.deep_scan owner/repo --since 2024-01-01 --until 2025-01-01")
        print("  python -m src.deep_scan owner/repo --max 1000")
        sys.exit(1)

    repo = sys.argv[1]
    since = None
    until = None
    max_commits = 5000

    args = sys.argv[2:]
    i = 0
    while i < len(args):
        if args[i] == "--since" and i + 1 < len(args):
            since = args[i + 1]
            if "T" not in since:
                since = f"{since}T00:00:00Z"
            i += 2
        elif args[i] == "--until" and i + 1 < len(args):
            until = args[i + 1]
            if "T" not in until:
                until = f"{until}T00:00:00Z"
            i += 2
        elif args[i] == "--max" and i + 1 < len(args):
            max_commits = int(args[i + 1])
            i += 2
        else:
            i += 1

    deep_scan(repo, since=since, until=until, max_commits=max_commits)