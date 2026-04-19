import json
import time
import sys
import requests
from datetime import datetime, timedelta, timezone
from src.config import DATA_DIR, GITHUB_TOKEN
from src.heuristics import score_commit
from src.fingerprint import match_fingerprints


SILENT_STATE_PATH = DATA_DIR / "silent_state.json"
SILENT_RESULTS_PATH = DATA_DIR / "silent_results.jsonl"
WATCHLIST_PATH = DATA_DIR / "watchlist.json"
GITHUB_API = "https://api.github.com"
REQUEST_DELAY = 0.8


def load_watchlist() -> list[str]:
    with open(WATCHLIST_PATH, "r") as f:
        data = json.load(f)
    return data.get("repos", [])


def load_silent_state() -> dict:
    if SILENT_STATE_PATH.exists():
        with open(SILENT_STATE_PATH, "r") as f:
            return json.load(f)
    return {
        "last_scan_at": "2000-01-01T00:00:00Z",
        "total_scanned": 0,
        "total_suspects": 0,
    }


def save_silent_state(state: dict):
    with open(SILENT_STATE_PATH, "w") as f:
        json.dump(state, f, indent=2, ensure_ascii=False)


def load_existing_results() -> set:
    seen = set()
    if SILENT_RESULTS_PATH.exists():
        with open(SILENT_RESULTS_PATH, "r") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    record = json.loads(line)
                except json.JSONDecodeError:
                    continue
                seen.add(record.get("commit_sha", ""))
    return seen


def append_result(result: dict):
    with open(SILENT_RESULTS_PATH, "a") as f:
        f.write(json.dumps(result, ensure_ascii=False) + "\n")


def github_get(endpoint: str, params: dict = None) -> dict | list | None:
    headers = {"Accept": "application/vnd.github.v3+json"}
    if GITHUB_TOKEN:
        headers["Authorization"] = f"Bearer {GITHUB_TOKEN}"

    url = f"{GITHUB_API}{endpoint}" if endpoint.startswith("/") else endpoint

    try:
        response = requests.get(url, headers=headers, params=params, timeout=30)
        if response.status_code == 403:
            remaining = response.headers.get("X-RateLimit-Remaining", "?")
            reset = response.headers.get("X-RateLimit-Reset", "0")
            if remaining == "0":
                wait = max(int(reset) - int(time.time()), 10)
                print(f"    Rate limited, waiting {wait}s...")
                time.sleep(wait)
                return github_get(endpoint, params)
            return None
        if response.status_code == 404:
            return None
        response.raise_for_status()
        return response.json()
    except requests.RequestException as exc:
        print(f"    API error: {exc}")
        return None


def run(hours: int = 24):
    now = datetime.now(timezone.utc)
    since = (now - timedelta(hours=hours)).isoformat()

    print(f"=== OSDC Silent Patch Scan {now.isoformat()} ===")
    print(f"Scanning commits since {since}")

    watchlist = load_watchlist()
    print(f"Watchlist: {len(watchlist)} repos")

    state = load_silent_state()
    seen_commits = load_existing_results()
    print(f"Already scanned: {len(seen_commits)} commits")

    total_commits = 0
    total_suspects = 0
    layer1_pass = 0
    layer2_pass = 0
    skipped_repos = 0

    for i, repo in enumerate(watchlist):
        print(f"  [{i+1}/{len(watchlist)}] {repo}...", end=" ", flush=True)

        commits = github_get(f"/repos/{repo}/commits", {"since": since, "per_page": 100})
        if not commits or not isinstance(commits, list):
            print("0 commits")
            skipped_repos += 1
            time.sleep(REQUEST_DELAY)
            continue

        new_commits = [c for c in commits if c.get("sha", "") not in seen_commits]
        print(f"{len(new_commits)} new", end="", flush=True)

        repo_suspects = 0

        for commit in new_commits:
            sha = commit.get("sha", "")
            message = commit.get("commit", {}).get("message", "").split("\n")[0]

            detail = github_get(f"/repos/{repo}/commits/{sha}")
            if not detail:
                time.sleep(REQUEST_DELAY)
                continue

            files = detail.get("files", [])
            if not files:
                continue

            total_commits += 1

            heuristic_result = score_commit(message, files)

            if not heuristic_result["threshold_met"]:
                continue

            layer1_pass += 1

            combined_patch = "\n".join(f.get("patch", "") for f in files if f.get("patch"))
            fingerprint_matches = match_fingerprints(combined_patch)

            best_fp = fingerprint_matches[0] if fingerprint_matches else None
            fp_score = best_fp["score"] if best_fp else 0.0

            normalized = heuristic_result["normalized_score"]
            if best_fp:
                normalized = min(normalized + (fp_score * 30), 100)

            if normalized < 20:
                continue

            layer2_pass += 1
            repo_suspects += 1
            total_suspects += 1

            top_file = heuristic_result["files"][0] if heuristic_result["files"] else {}

            result = {
                "commit_sha": sha,
                "repo": repo,
                "commit_url": f"https://github.com/{repo}/commit/{sha}",
                "message": message[:200],
                "date": detail.get("commit", {}).get("author", {}).get("date", ""),
                "author": detail.get("commit", {}).get("author", {}).get("name", ""),
                "normalized_score": round(normalized, 1),
                "heuristic_score": heuristic_result["score"],
                "heuristic_normalized": heuristic_result["normalized_score"],
                "top_file": top_file.get("file", ""),
                "top_file_score": top_file.get("score", 0),
                "top_file_signals": top_file.get("signals", []),
                "added_sample": top_file.get("added_sample", "")[:300],
                "removed_sample": top_file.get("removed_sample", "")[:300],
                "fingerprint_match": best_fp["pattern_name"] if best_fp else None,
                "fingerprint_score": fp_score,
                "fingerprint_matched_tokens": (best_fp["matched_add_tokens"][:5] if best_fp else []),
                "files_changed": len(files),
                "scan_date": now.isoformat(),
                "status": "SUSPECT",
            }

            append_result(result)
            print(f"\n    SUSPECT: {sha[:8]} score={normalized:.1f} {top_file.get('file', '?')}", end="", flush=True)

            time.sleep(REQUEST_DELAY)

        if repo_suspects == 0:
            print(" clean")
        else:
            print(f" {repo_suspects} suspect(s)")

        time.sleep(REQUEST_DELAY)

    state = {
        "last_scan_at": now.isoformat(),
        "total_scanned": state.get("total_scanned", 0) + total_commits,
        "total_suspects": state.get("total_suspects", 0) + total_suspects,
    }
    save_silent_state(state)

    print("\n=== Summary ===")
    print(f"Repos scanned: {len(watchlist) - skipped_repos}/{len(watchlist)}")
    print(f"Commits analyzed: {total_commits}")
    print(f"Layer 1 pass (heuristics >= 8): {layer1_pass}")
    print(f"Layer 2 pass (normalized >= 10): {layer2_pass}")
    print(f"New suspects: {total_suspects}")
    print(f"Total suspects in DB: {state['total_suspects']}")


if __name__ == "__main__":
    hours = int(sys.argv[1]) if len(sys.argv) > 1 else 24
    run(hours)