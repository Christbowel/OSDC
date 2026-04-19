import re
import time
import requests
from typing import Optional
from src.config import (
    GITHUB_TOKEN, GITHUB_GRAPHQL_URL, GHSA_QUERY,
    SEVERITY_PRIORITY, RETRY_ATTEMPTS, RETRY_BACKOFF,
)


ECOSYSTEM_LANG_MAP = {
    "NPM": "JavaScript",
    "PYPI": "Python",
    "GO": "Go",
    "MAVEN": "Java",
    "NUGET": "C#",
    "RUBYGEMS": "Ruby",
    "PACKAGIST": "PHP",
    "CRATES_IO": "Rust",
    "PUB": "Dart",
    "ERLANG": "Erlang",
    "ACTIONS": "YAML",
    "SWIFT": "Swift",
}


def graphql_request(query: str, variables: dict) -> dict:
    headers = {
        "Authorization": f"Bearer {GITHUB_TOKEN}",
        "Content-Type": "application/json",
    }
    payload = {"query": query, "variables": variables}

    for attempt in range(RETRY_ATTEMPTS):
        try:
            response = requests.post(
                GITHUB_GRAPHQL_URL,
                json=payload,
                headers=headers,
                timeout=30,
            )
            if response.status_code == 403:
                remaining = response.headers.get("X-RateLimit-Remaining", "?")
                reset_at = response.headers.get("X-RateLimit-Reset", "0")
                if remaining == "0":
                    wait = max(int(reset_at) - int(time.time()), 10)
                    print(f"  GraphQL rate limited, waiting {wait}s...")
                    time.sleep(wait)
                    return graphql_request(query, variables)
                print(f"  GraphQL 403 (remaining: {remaining})")
                return {}
            response.raise_for_status()
            data = response.json()
            if "errors" in data:
                print(f"  GraphQL errors: {data['errors'][:200]}")
                return {}
            return data
        except requests.RequestException as exc:
            if attempt == RETRY_ATTEMPTS - 1:
                print(f"  GraphQL request failed: {exc}")
                return {}
            time.sleep(RETRY_BACKOFF[attempt])

    return {}


def fetch_advisories(since: str) -> list[dict]:
    all_advisories = []
    cursor = None

    while True:
        variables = {"since": since, "cursor": cursor}
        data = graphql_request(GHSA_QUERY, variables)
        advisory_data = data.get("data", {}).get("securityAdvisories", {})
        nodes = advisory_data.get("nodes", [])

        for node in nodes:
            parsed = _parse_advisory(node)
            if parsed:
                all_advisories.append(parsed)

        page_info = advisory_data.get("pageInfo", {})
        if page_info.get("hasNextPage"):
            cursor = page_info["endCursor"]
        else:
            break

    all_advisories.sort(
        key=lambda a: SEVERITY_PRIORITY.get(a["severity"], 99)
    )

    return all_advisories


def _parse_advisory(node: dict) -> Optional[dict]:
    ghsa_id = node.get("ghsaId", "")
    references = node.get("references", [])
    commit_url = _extract_commit_url(references)

    if not commit_url:
        return None

    vulns = node.get("vulnerabilities", {}).get("nodes", [])
    package_info = _extract_package_info(vulns)

    cve_id = _extract_cve_id(node.get("identifiers", []))

    ecosystem = package_info["ecosystem"]
    language = ECOSYSTEM_LANG_MAP.get(ecosystem.upper(), ecosystem)

    return {
        "ghsa_id": ghsa_id,
        "cve_id": cve_id,
        "summary": node.get("summary", ""),
        "description": node.get("description", ""),
        "severity": node.get("severity", "UNKNOWN"),
        "cvss_score": node.get("cvss", {}).get("score", 0.0),
        "published_at": node.get("publishedAt", ""),
        "commit_url": commit_url,
        "package_name": package_info["name"],
        "ecosystem": ecosystem,
        "language": language,
        "repo": _extract_repo_from_commit(commit_url),
    }


def _extract_cve_id(identifiers: list[dict]) -> str:
    for ident in identifiers:
        if ident.get("type") == "CVE":
            return ident.get("value", "")
    return ""


def _extract_commit_url(references: list[dict]) -> Optional[str]:
    commit_pattern = re.compile(
        r"https://github\.com/[^/]+/[^/]+/commit/[0-9a-f]{7,40}"
    )
    for ref in references:
        url = ref.get("url", "")
        if commit_pattern.match(url):
            return url
    return None


def _extract_package_info(vulns: list[dict]) -> dict:
    if not vulns:
        return {"name": "unknown", "ecosystem": "unknown"}

    first_vuln = vulns[0]
    pkg = first_vuln.get("package", {})
    return {
        "name": pkg.get("name", "unknown"),
        "ecosystem": pkg.get("ecosystem", "unknown"),
    }


def _extract_repo_from_commit(commit_url: str) -> str:
    match = re.match(
        r"https://github\.com/([^/]+/[^/]+)/commit/", commit_url
    )
    return match.group(1) if match else "unknown/unknown"


def fetch_commit_diff(commit_url: str) -> Optional[str]:
    headers = {
        "Authorization": f"Bearer {GITHUB_TOKEN}",
        "Accept": "application/vnd.github.v3.diff",
    }

    api_url = commit_url.replace(
        "https://github.com/", "https://api.github.com/repos/"
    ).replace("/commit/", "/commits/")

    for attempt in range(RETRY_ATTEMPTS):
        try:
            response = requests.get(
                api_url, headers=headers, timeout=30
            )
            if response.status_code == 403:
                remaining = response.headers.get("X-RateLimit-Remaining", "?")
                reset_at = response.headers.get("X-RateLimit-Reset", "0")
                if remaining == "0":
                    wait = max(int(reset_at) - int(time.time()), 10)
                    print(f"  Diff rate limited, waiting {wait}s...")
                    time.sleep(wait)
                    return fetch_commit_diff(commit_url)
                return None
            if response.status_code == 404:
                return None
            response.raise_for_status()
            return response.text
        except requests.RequestException:
            if attempt == RETRY_ATTEMPTS - 1:
                return None
            time.sleep(RETRY_BACKOFF[attempt])

    return None
