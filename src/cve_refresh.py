import json
import time
from src.config import (
    GITHUB_TOKEN, GITHUB_GRAPHQL_URL, JSONL_PATH,
    RETRY_ATTEMPTS, RETRY_BACKOFF,
)
from src.db import rebuild_from_jsonl, export_to_jsonl
import requests


GHSA_LOOKUP_QUERY = """
query($id: String!) {
  securityAdvisory(ghsaId: $id) {
    ghsaId
    identifiers {
      type
      value
    }
  }
}
"""

REQUEST_DELAY = 1.5


def _graphql(query: str, variables: dict) -> dict:
    headers = {
        "Authorization": f"Bearer {GITHUB_TOKEN}",
        "Content-Type": "application/json",
    }

    for attempt in range(RETRY_ATTEMPTS):
        try:
            response = requests.post(
                GITHUB_GRAPHQL_URL,
                json={"query": query, "variables": variables},
                headers=headers,
                timeout=30,
            )
            if response.status_code == 403:
                remaining = response.headers.get("X-RateLimit-Remaining", "?")
                reset_at = response.headers.get("X-RateLimit-Reset", "0")
                if remaining == "0":
                    wait = max(int(reset_at) - int(time.time()), 10)
                    print(f"  Rate limited, waiting {wait}s...")
                    time.sleep(wait)
                    return _graphql(query, variables)
                return {}
            response.raise_for_status()
            data = response.json()
            if "errors" in data:
                print(f"  GraphQL error: {data['errors'][:200]}")
                return {}
            return data
        except requests.RequestException as exc:
            if attempt == RETRY_ATTEMPTS - 1:
                print(f"  Request failed: {exc}")
                return {}
            time.sleep(RETRY_BACKOFF[attempt])

    return {}


def run():
    print("=== OSDC CVE Refresh ===")

    if not JSONL_PATH.exists():
        print("No JSONL found, nothing to refresh")
        return

    records = []
    no_cve = []

    with open(JSONL_PATH) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue
            records.append(record)
            if record.get("_type") == "advisory" and not record.get("cve_id", ""):
                no_cve.append(record)

    print(f"Total records: {len(records)}")
    print(f"Advisories without CVE: {len(no_cve)}")

    if not no_cve:
        print("All advisories have CVE IDs, nothing to refresh")
        return

    updated = 0
    checked = 0

    for i, adv in enumerate(no_cve):
        ghsa_id = adv.get("id", "")
        if not ghsa_id:
            continue

        print(f"  [{i + 1}/{len(no_cve)}] {ghsa_id}...", end=" ")

        data = _graphql(GHSA_LOOKUP_QUERY, {"id": ghsa_id})
        advisory_data = data.get("data", {}).get("securityAdvisory")

        if not advisory_data:
            print("not found")
            time.sleep(REQUEST_DELAY)
            checked += 1
            continue

        identifiers = advisory_data.get("identifiers", [])
        cve_id = ""
        for ident in identifiers:
            if ident.get("type") == "CVE":
                cve_id = ident.get("value", "")
                break

        if cve_id:
            adv["cve_id"] = cve_id
            print(f"CVE assigned: {cve_id}")
            updated += 1
        else:
            print("still no CVE")

        checked += 1
        time.sleep(REQUEST_DELAY)

    if updated > 0:
        print(f"\nUpdating JSONL with {updated} new CVE IDs...")
        ghsa_to_cve = {a["id"]: a["cve_id"] for a in no_cve if a.get("cve_id")}

        tmp_path = JSONL_PATH.with_suffix(".jsonl.tmp")
        with open(tmp_path, "w") as f:
            for record in records:
                if record.get("_type") == "advisory" and record.get("id", "") in ghsa_to_cve:
                    record["cve_id"] = ghsa_to_cve[record["id"]]
                f.write(json.dumps(record, ensure_ascii=False) + "\n")

        import os
        os.replace(tmp_path, JSONL_PATH)
        print("JSONL updated")

        rebuild_from_jsonl()
        print("DB rebuilt")

    print(f"\n=== Summary ===")
    print(f"Checked: {checked}")
    print(f"CVE assigned: {updated}")
    print(f"Still without CVE: {len(no_cve) - updated}")


if __name__ == "__main__":
    run()
