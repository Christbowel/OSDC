import time
import requests
from src.config import GITHUB_TOKEN


GITHUB_API = "https://api.github.com"
REQUEST_DELAY = 0.8


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
                print(f"  Rate limited, waiting {wait}s...")
                time.sleep(wait)
                return github_get(endpoint, params)
            print(f"  Rate limited (remaining: {remaining})")
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
