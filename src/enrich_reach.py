import json
import re
import sys
import time
import base64
import requests
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Optional
from src.config import DATA_DIR, GITHUB_TOKEN
from src.db import rebuild_from_jsonl, get_all_advisories


ENRICH_DIR = DATA_DIR / "enrichments" / "reach"
REPO_PKG_CACHE = DATA_DIR / "enrichments" / "_repo_packages.json"
SILENT_PATH = DATA_DIR / "silent_results.jsonl"
DEPSDEV_BASE = "https://api.deps.dev/v3"
TTL_DAYS = 7
RATE_DELAY = 0.18

LANG_TO_ECO = {
    "JavaScript": "npm",
    "TypeScript": "npm",
    "Python": "pypi",
    "Java": "maven",
    "Go": "go",
    "Rust": "cargo",
    "C#": "nuget",
    "NPM": "npm",
    "PYPI": "pypi",
    "MAVEN": "maven",
    "GO": "go",
    "CARGO": "cargo",
    "CRATES_IO": "cargo",
    "NUGET": "nuget",
}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _is_fresh(cached: dict) -> bool:
    enriched_at = cached.get("enriched_at", "")
    if not enriched_at:
        return False
    try:
        ts = datetime.fromisoformat(enriched_at.replace("Z", "+00:00"))
    except ValueError:
        return False
    return (datetime.now(timezone.utc) - ts) < timedelta(days=TTL_DAYS)


def _load_repo_pkg_cache() -> dict:
    if REPO_PKG_CACHE.exists():
        try:
            return json.loads(REPO_PKG_CACHE.read_text())
        except json.JSONDecodeError:
            return {}
    return {}


def _save_repo_pkg_cache(cache: dict):
    REPO_PKG_CACHE.parent.mkdir(parents=True, exist_ok=True)
    REPO_PKG_CACHE.write_text(json.dumps(cache, indent=2, ensure_ascii=False))


def _gh_get(path: str, accept: str = "application/vnd.github.v3+json") -> Optional[dict]:
    headers = {"Accept": accept}
    if GITHUB_TOKEN:
        headers["Authorization"] = f"Bearer {GITHUB_TOKEN}"
    try:
        r = requests.get(f"https://api.github.com{path}", headers=headers, timeout=20)
        if r.status_code == 200:
            return r.json() if accept.endswith("json") else {"raw": r.text}
        if r.status_code == 403 and r.headers.get("X-RateLimit-Remaining") == "0":
            reset = int(r.headers.get("X-RateLimit-Reset", "0"))
            wait = max(reset - int(time.time()), 5)
            print(f"    GH rate limit, sleeping {wait}s")
            time.sleep(min(wait, 60))
            return _gh_get(path, accept)
        return None
    except requests.RequestException:
        return None


def _depsdev_get(path: str) -> Optional[dict]:
    try:
        r = requests.get(f"{DEPSDEV_BASE}{path}", timeout=15)
        if r.status_code == 200:
            return r.json()
        if r.status_code == 429:
            time.sleep(2)
            return _depsdev_get(path)
        return None
    except requests.RequestException:
        return None


def _fetch_manifest_file(repo: str, filename: str) -> Optional[str]:
    data = _gh_get(f"/repos/{repo}/contents/{filename}")
    if not data or "content" not in data:
        return None
    try:
        return base64.b64decode(data["content"]).decode("utf-8", errors="replace")
    except Exception:
        return None


def _parse_npm_name(content: str) -> Optional[str]:
    try:
        data = json.loads(content)
        name = data.get("name", "")
        if name and not name.startswith("@types/"):
            return name
    except json.JSONDecodeError:
        pass
    return None


def _parse_pypi_name(content: str, filename: str) -> Optional[str]:
    if filename == "pyproject.toml":
        m = re.search(r'(?m)^\s*name\s*=\s*[\'"]([^\'"]+)[\'"]', content)
        if m:
            return m.group(1)
    if filename == "setup.py":
        m = re.search(r'name\s*=\s*[\'"]([^\'"]+)[\'"]', content)
        if m:
            return m.group(1)
    if filename == "setup.cfg":
        m = re.search(r'(?m)^\s*name\s*=\s*(\S+)', content)
        if m:
            return m.group(1).strip()
    return None


def _parse_cargo_name(content: str) -> Optional[str]:
    m = re.search(r'(?ms)\[package\].*?^\s*name\s*=\s*[\'"]([^\'"]+)[\'"]', content)
    if m:
        return m.group(1)
    return None


def _parse_go_module(content: str) -> Optional[str]:
    m = re.search(r'(?m)^\s*module\s+(\S+)', content)
    if m:
        return m.group(1).strip()
    return None


def resolve_repo_to_package(repo: str, cache: dict) -> Optional[dict]:
    if repo in cache:
        return cache[repo]

    candidates = [
        ("package.json", "npm", _parse_npm_name),
        ("pyproject.toml", "pypi", lambda c: _parse_pypi_name(c, "pyproject.toml")),
        ("setup.py", "pypi", lambda c: _parse_pypi_name(c, "setup.py")),
        ("setup.cfg", "pypi", lambda c: _parse_pypi_name(c, "setup.cfg")),
        ("Cargo.toml", "cargo", _parse_cargo_name),
        ("go.mod", "go", _parse_go_module),
    ]

    for filename, ecosystem, parser in candidates:
        content = _fetch_manifest_file(repo, filename)
        if content:
            name = parser(content)
            if name:
                result = {
                    "name": name,
                    "ecosystem": ecosystem,
                    "source": filename,
                    "resolved_at": _now(),
                }
                cache[repo] = result
                return result

    cache[repo] = {"name": None, "ecosystem": None, "source": "not_found", "resolved_at": _now()}
    return cache[repo]


def fetch_depsdev_package(name: str, ecosystem: str) -> Optional[dict]:
    safe_name = requests.utils.quote(name, safe="")
    data = _depsdev_get(f"/systems/{ecosystem}/packages/{safe_name}")
    if not data:
        return None

    versions = data.get("versions", [])
    if not versions:
        return None

    default_ver = None
    for v in versions:
        if v.get("isDefault"):
            default_ver = v.get("versionKey", {}).get("version")
            break
    if not default_ver and versions:
        default_ver = versions[-1].get("versionKey", {}).get("version")

    return {
        "name": name,
        "ecosystem": ecosystem,
        "default_version": default_ver,
        "version_count": len(versions),
    }


def fetch_depsdev_dependents(name: str, ecosystem: str, version: Optional[str]) -> dict:
    if not version:
        return {"direct": 0, "indirect": 0, "total": 0, "source": "skipped"}

    safe_name = requests.utils.quote(name, safe="")
    safe_ver = requests.utils.quote(version, safe="")
    data = _depsdev_get(
        f"/systems/{ecosystem}/packages/{safe_name}/versions/{safe_ver}:dependents"
    )
    if not data:
        return {"direct": 0, "indirect": 0, "total": 0, "source": "deps.dev_miss"}

    return {
        "direct": data.get("directDependentCount", 0),
        "indirect": data.get("indirectDependentCount", 0),
        "total": data.get("totalDependentCount", 0),
        "source": "deps.dev",
    }


def fetch_npm_downloads(name: str) -> dict:
    safe = requests.utils.quote(name, safe="@/")
    try:
        r = requests.get(f"https://api.npmjs.org/downloads/point/last-week/{safe}", timeout=10)
        weekly = r.json().get("downloads", 0) if r.status_code == 200 else 0
    except requests.RequestException:
        weekly = 0

    timeline = []
    labels = []
    try:
        end = datetime.now(timezone.utc).date()
        start = end - timedelta(weeks=12)
        r = requests.get(
            f"https://api.npmjs.org/downloads/range/{start}:{end}/{safe}",
            timeout=15,
        )
        if r.status_code == 200:
            data = r.json().get("downloads", [])
            week = []
            week_start = None
            for d in data:
                day_date = datetime.strptime(d["day"], "%Y-%m-%d").date()
                if week_start is None:
                    week_start = day_date
                week.append(d.get("downloads", 0))
                if (day_date - week_start).days >= 6:
                    timeline.append(sum(week))
                    labels.append(week_start.isoformat())
                    week = []
                    week_start = None
            if week:
                timeline.append(sum(week))
                labels.append(week_start.isoformat() if week_start else "")
    except requests.RequestException:
        pass

    return {
        "weekly": weekly,
        "monthly": weekly * 4 if weekly else 0,
        "source": "npmjs.org",
        "timeline_12w": timeline[-12:],
        "timeline_labels": labels[-12:],
    }


def fetch_pypi_downloads(name: str) -> dict:
    safe = requests.utils.quote(name, safe="")
    weekly = 0
    monthly = 0
    try:
        r = requests.get(f"https://pypistats.org/api/packages/{safe}/recent", timeout=10)
        if r.status_code == 200:
            d = r.json().get("data", {})
            weekly = d.get("last_week", 0)
            monthly = d.get("last_month", 0)
    except requests.RequestException:
        pass

    timeline = []
    labels = []
    try:
        r = requests.get(f"https://pypistats.org/api/packages/{safe}/system", timeout=15)
        if r.status_code == 200:
            rows = r.json().get("data", [])
            by_date = {}
            for row in rows:
                d = row.get("date", "")
                by_date[d] = by_date.get(d, 0) + row.get("downloads", 0)
            sorted_dates = sorted(by_date.keys())[-84:]
            week_bucket = []
            for i, d in enumerate(sorted_dates):
                week_bucket.append(by_date[d])
                if len(week_bucket) == 7:
                    timeline.append(sum(week_bucket))
                    labels.append(sorted_dates[i - 6])
                    week_bucket = []
            if week_bucket:
                timeline.append(sum(week_bucket))
                labels.append(sorted_dates[-len(week_bucket)])
    except requests.RequestException:
        pass

    return {
        "weekly": weekly,
        "monthly": monthly,
        "source": "pypistats.org",
        "timeline_12w": timeline[-12:],
        "timeline_labels": labels[-12:],
    }


def fetch_downloads(name: str, ecosystem: str) -> dict:
    if ecosystem == "npm":
        return fetch_npm_downloads(name)
    if ecosystem == "pypi":
        return fetch_pypi_downloads(name)
    return {"weekly": 0, "monthly": 0, "source": "unsupported", "timeline_12w": [], "timeline_labels": []}


def compute_blast_radius(downloads: dict, dependents: dict) -> dict:
    weekly = downloads.get("weekly", 0) or 0
    direct = dependents.get("direct", 0) or 0
    indirect = dependents.get("indirect", 0) or 0

    score = 0
    factors = []

    if weekly >= 10_000_000:
        score += 40; factors.append("downloads:10M+/wk")
    elif weekly >= 1_000_000:
        score += 30; factors.append("downloads:1M+/wk")
    elif weekly >= 100_000:
        score += 20; factors.append("downloads:100K+/wk")
    elif weekly >= 10_000:
        score += 10; factors.append("downloads:10K+/wk")
    elif weekly > 0:
        score += 3; factors.append("downloads:low")

    if direct >= 100_000:
        score += 35; factors.append("dependents_direct:100K+")
    elif direct >= 10_000:
        score += 25; factors.append("dependents_direct:10K+")
    elif direct >= 1_000:
        score += 15; factors.append("dependents_direct:1K+")
    elif direct >= 100:
        score += 8; factors.append("dependents_direct:100+")
    elif direct > 0:
        score += 3

    if indirect >= 1_000_000:
        score += 20; factors.append("transitive:1M+")
    elif indirect >= 100_000:
        score += 12; factors.append("transitive:100K+")
    elif indirect >= 10_000:
        score += 6; factors.append("transitive:10K+")

    if score >= 70:
        tier = "CRITICAL"
    elif score >= 45:
        tier = "HIGH"
    elif score >= 20:
        tier = "MEDIUM"
    elif score > 0:
        tier = "LOW"
    else:
        tier = "UNKNOWN"

    return {"score": min(score, 100), "tier": tier, "factors": factors}


def enrich_record(record_id: str, axis: str, package: Optional[str], ecosystem: Optional[str], repo: str, repo_pkg_cache: dict) -> dict:
    eco = None
    pkg = None
    pkg_source = None

    if package and ecosystem:
        eco = LANG_TO_ECO.get(ecosystem) or LANG_TO_ECO.get(ecosystem.upper())
        if eco:
            pkg = package
            pkg_source = "advisory_field"

    if not pkg and repo:
        resolved = resolve_repo_to_package(repo, repo_pkg_cache)
        if resolved and resolved.get("name"):
            pkg = resolved["name"]
            eco = resolved["ecosystem"]
            pkg_source = resolved.get("source", "repo_manifest")

    if not pkg or not eco:
        return {
            "id": record_id,
            "axis": axis,
            "repo": repo,
            "package": None,
            "downloads": None,
            "dependents": None,
            "blast_radius": {"score": 0, "tier": "UNKNOWN", "factors": []},
            "enriched_at": _now(),
        }

    pkg_info = fetch_depsdev_package(pkg, eco)
    time.sleep(RATE_DELAY)
    default_ver = pkg_info.get("default_version") if pkg_info else None

    dependents = fetch_depsdev_dependents(pkg, eco, default_ver)
    time.sleep(RATE_DELAY)

    downloads = fetch_downloads(pkg, eco)
    time.sleep(RATE_DELAY)

    blast = compute_blast_radius(downloads, dependents)

    return {
        "id": record_id,
        "axis": axis,
        "repo": repo,
        "package": {
            "name": pkg,
            "ecosystem": eco,
            "version": default_ver,
            "source": pkg_source,
            "version_count": pkg_info.get("version_count") if pkg_info else None,
        },
        "downloads": downloads,
        "dependents": dependents,
        "blast_radius": blast,
        "enriched_at": _now(),
    }


def load_targets() -> list[dict]:
    rebuild_from_jsonl()
    advisories = get_all_advisories()
    targets = []

    for a in advisories:
        targets.append({
            "id": a["id"],
            "axis": "advisories",
            "package": a.get("package_name") or None,
            "ecosystem": a.get("language") or None,
            "repo": a.get("repo", ""),
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
                targets.append({
                    "id": s.get("commit_sha", ""),
                    "axis": "silent",
                    "package": None,
                    "ecosystem": None,
                    "repo": s.get("repo", ""),
                })

    return targets


def run(limit: Optional[int] = None):
    ENRICH_DIR.mkdir(parents=True, exist_ok=True)

    targets = load_targets()
    print(f"=== OSDC Reach Enrichment === ({len(targets)} candidates)")

    repo_pkg_cache = _load_repo_pkg_cache()
    print(f"Repo→package cache: {len(repo_pkg_cache)} entries")

    new_count = 0
    skipped = 0
    processed = 0
    failed = 0
    started_at = time.time()

    for t in targets:
        record_id = t["id"]
        if not record_id:
            continue

        cache_path = ENRICH_DIR / f"{record_id}.json"
        if cache_path.exists():
            try:
                cached = json.loads(cache_path.read_text())
                if _is_fresh(cached):
                    skipped += 1
                    continue
            except json.JSONDecodeError:
                pass

        try:
            enriched = enrich_record(
                record_id=record_id,
                axis=t["axis"],
                package=t["package"],
                ecosystem=t["ecosystem"],
                repo=t["repo"],
                repo_pkg_cache=repo_pkg_cache,
            )
            cache_path.write_text(json.dumps(enriched, ensure_ascii=False, separators=(",", ":")))
            new_count += 1
            processed += 1
            tier = enriched.get("blast_radius", {}).get("tier", "?")
            pkg_name = (enriched.get("package") or {}).get("name") or "—"
            print(f"  [{processed}/{len(targets)}] {record_id[:12]} {tier:9} {pkg_name}")
        except Exception as exc:
            failed += 1
            print(f"  [FAIL] {record_id[:12]}: {exc}")

        if processed % 25 == 0:
            _save_repo_pkg_cache(repo_pkg_cache)

        if limit and new_count >= limit:
            print(f"  [LIMIT {limit} reached]")
            break

    _save_repo_pkg_cache(repo_pkg_cache)

    elapsed = time.time() - started_at
    print(f"\n=== Summary ===")
    print(f"New enrichments: {new_count}")
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
