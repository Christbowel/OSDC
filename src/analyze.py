import json
import time
import requests
from typing import Optional
from src.config import (
    GEMINI_API_KEY, GEMINI_API_URL,
    LLM_SYSTEM_PROMPT, LLM_USER_PROMPT_TEMPLATE,
    TAXONOMY_PATH, RETRY_ATTEMPTS, RETRY_BACKOFF,
    RATE_LIMIT_DELAY,
)


_taxonomy_cache: Optional[list[str]] = None


def load_taxonomy() -> list[str]:
    global _taxonomy_cache
    if _taxonomy_cache is not None:
        return _taxonomy_cache

    with open(TAXONOMY_PATH, "r") as f:
        data = json.load(f)

    _taxonomy_cache = [p["id"] for p in data["patterns"]]
    return _taxonomy_cache


def analyze_advisory(advisory: dict, filtered_diff: str) -> Optional[dict]:
    taxonomy_ids = load_taxonomy()
    taxonomy_list = "\n".join(f"- {pid}" for pid in taxonomy_ids)

    user_prompt = LLM_USER_PROMPT_TEMPLATE.format(
        ghsa_id=advisory["ghsa_id"],
        severity=advisory["severity"],
        cvss_score=advisory["cvss_score"],
        summary=advisory["summary"],
        package_name=advisory["package_name"],
        ecosystem=advisory["ecosystem"],
        diff_content=filtered_diff[:8000],
        taxonomy_list=taxonomy_list,
    )

    raw_response = _call_gemini(user_prompt)
    if not raw_response:
        print(f"    DEBUG: _call_gemini returned None")
        return None

    parsed = _parse_llm_response(raw_response)
    if not parsed:
        print(f"    DEBUG: parse failed, raw response: {raw_response[:300]}")
        return None
        
    if parsed.get("pattern_id") not in taxonomy_ids:
        parsed["pattern_id"] = "UNCLASSIFIED"

    return {
        "ghsa_id": advisory["ghsa_id"],
        "date": advisory["published_at"][:10],
        "cve_id": "",
        "repo": advisory["repo"],
        "language": _ecosystem_to_language(advisory["ecosystem"]),
        "severity": advisory["severity"],
        "cvss_score": advisory["cvss_score"],
        "package_name": advisory["package_name"],
        "pattern_id": parsed["pattern_id"],
        "vuln_type": parsed.get("vuln_type", ""),
        "root_cause": parsed.get("root_cause", ""),
        "impact": parsed.get("impact", ""),
        "fix_summary": parsed.get("fix_summary", ""),
        "key_diff": parsed.get("key_diff", ""),
        "confidence": parsed.get("confidence", "LOW"),
        "commit_url": advisory["commit_url"],
    }


def _call_gemini(user_prompt: str) -> Optional[str]:
    url = f"{GEMINI_API_URL}?key={GEMINI_API_KEY}"
    payload = {
        "system_instruction": {
            "parts": [{"text": LLM_SYSTEM_PROMPT}]
        },
        "contents": [
            {"role": "user", "parts": [{"text": user_prompt}]}
        ],
        "generationConfig": {
            "temperature": 0.2,
            "maxOutputTokens": 8192,
            "responseMimeType": "application/json",
            "thinkingConfig": {"thinkingBudget": 0},
        },
    }

    for attempt in range(RETRY_ATTEMPTS):
        try:
            response = requests.post(url, json=payload, timeout=60)

            if response.status_code == 429:
                print(f"    HTTP 429: {response.text[:500]}")
                return None

            if response.status_code != 200:
                print(f"    Gemini HTTP {response.status_code}: {response.text[:300]}")
                return None

            data = response.json()
            candidates = data.get("candidates", [])
            if not candidates:
                print(f"    Gemini: no candidates in response")
                return None

            content = candidates[0].get("content", {})
            parts = content.get("parts", [])
            if not parts:
                print(f"    Gemini: no parts in response")
                return None

            return parts[0].get("text", "")

        except requests.RequestException as exc:
            print(f"    Gemini error (attempt {attempt+1}): {exc}")
            if attempt == RETRY_ATTEMPTS - 1:
                return None
            time.sleep(RETRY_BACKOFF[attempt])

    return None

def _parse_llm_response(raw: str) -> Optional[dict]:
    cleaned = raw.strip()
    if cleaned.startswith("```"):
        lines = cleaned.splitlines()
        cleaned = "\n".join(lines[1:-1])

    try:
        return json.loads(cleaned)
    except json.JSONDecodeError:
        return None


def _ecosystem_to_language(ecosystem: str) -> str:
    mapping = {
        "NPM": "JavaScript",
        "GO": "Go",
        "PIP": "Python",
        "PYPI": "Python",
        "MAVEN": "Java",
        "NUGET": "C#",
        "RUBYGEMS": "Ruby",
        "CRATES_IO": "Rust",
        "COMPOSER": "PHP",
        "CARGO": "Rust",
        "HEX": "Elixir",
        "PUB": "Dart",
        "SWIFT": "Swift",
        "ACTIONS": "YAML",
        "ERLANG": "Erlang",
    }
    return mapping.get(ecosystem.upper(), ecosystem)
