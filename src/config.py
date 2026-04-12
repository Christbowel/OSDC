import os
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent
SRC_DIR = ROOT_DIR / "src"
DATA_DIR = ROOT_DIR / "data"
PATCHES_DIR = ROOT_DIR / "patches"
DOCS_DIR = ROOT_DIR / "docs"
TEMPLATES_DIR = ROOT_DIR / "templates"
DB_PATH = ROOT_DIR / "db" / "patterns.sqlite"
JSONL_PATH = DATA_DIR / "patterns.jsonl"
STATE_PATH = DATA_DIR / "state.json"
TAXONOMY_PATH = DATA_DIR / "taxonomy.json"

GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN", "")
GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY", "")

GITHUB_GRAPHQL_URL = "https://api.github.com/graphql"
GEMINI_API_URL = (
    "https://generativelanguage.googleapis.com/v1beta/models/"
    "gemini-2.5-flash:generateContent"
)

MAX_DAILY_CALLS = 50
MAX_DIFF_FILES = 5
MAX_DIFF_LINES = 500
RATE_LIMIT_DELAY = 3.0
RETRY_ATTEMPTS = 3
RETRY_BACKOFF = [2, 4, 8]

SEVERITY_PRIORITY = {"CRITICAL": 0, "HIGH": 1, "MODERATE": 2, "MEDIUM": 2, "LOW": 3}

EXCLUDED_EXTENSIONS = {
    ".md", ".txt", ".rst", ".yml", ".yaml", ".toml", ".cfg", ".ini",
    ".lock", ".sum", ".mod", ".json", ".xml", ".csv",
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
    ".woff", ".woff2", ".ttf", ".eot",
    ".min.js", ".min.css", ".map",
}

EXCLUDED_PATTERNS = [
    "test_", "_test.", ".test.", "tests/", "test/", "spec/", "specs/",
    "__tests__", "__mocks__", "fixtures/", "testdata/",
    "docs/", "doc/", "documentation/",
    "vendor/", "node_modules/", "dist/", "build/",
    ".github/", ".circleci/", ".gitlab-ci",
    "changelog", "CHANGELOG", "CHANGES", "HISTORY",
    "LICENSE", "NOTICE", "AUTHORS", "CONTRIBUTORS",
    "Makefile", "Dockerfile", "docker-compose",
    "package-lock.json", "yarn.lock", "Gemfile.lock",
    "go.sum", "Cargo.lock", "poetry.lock",
    "migration", "schema.sql", "seed",
]

SECURITY_KEYWORDS = [
    "auth", "login", "password", "credential", "token", "session",
    "sanitiz", "escap", "encod", "validat", "filter",
    "query", "sql", "inject", "xss", "csrf",
    "encrypt", "decrypt", "hash", "hmac", "sign", "verify",
    "permission", "privilege", "access", "role", "policy",
    "input", "parse", "deserializ", "unmarshal",
    "path", "file", "directory", "traversal",
    "redirect", "url", "origin", "cors", "header",
    "random", "nonce", "salt", "key", "secret",
    "timeout", "limit", "throttl", "rate",
    "buffer", "overflow", "bound", "length", "size",
]

GHSA_QUERY = """
query($since: DateTime!, $cursor: String) {
  securityAdvisories(
    first: 100,
    publishedSince: $since,
    orderBy: {field: PUBLISHED_AT, direction: DESC},
    after: $cursor
  ) {
    pageInfo {
      hasNextPage
      endCursor
    }
    nodes {
      ghsaId
      summary
      description
      severity
      cvss {
        score
      }
      publishedAt
      vulnerabilities(first: 5) {
        nodes {
          package {
            name
            ecosystem
          }
          vulnerableVersionRange
        }
      }
      references {
        url
      }
    }
  }
}
"""

LLM_SYSTEM_PROMPT = """You are a security vulnerability analyst. You analyze code diffs from security patches and extract structured information.

You MUST respond with valid JSON only. No markdown, no explanation, no preamble.

The JSON schema:
{
  "vuln_type": "Short vulnerability type (e.g., SQL Injection, XSS, SSRF)",
  "root_cause": "2-3 sentences explaining why the vulnerability existed",
  "impact": "1-2 sentences on what an attacker could achieve",
  "fix_summary": "2-3 sentences explaining what the patch does",
  "pattern_id": "MUST be one from the provided taxonomy list, or UNCLASSIFIED if none fits",
  "key_diff": "The single most important code change (before→after), max 3 lines each side",
  "confidence": "HIGH, MEDIUM, or LOW"
}"""

LLM_USER_PROMPT_TEMPLATE = """Analyze this security patch.

ADVISORY: {ghsa_id}
SEVERITY: {severity} (CVSS: {cvss_score})
SUMMARY: {summary}
PACKAGE: {package_name} ({ecosystem})

DIFF:
```
{diff_content}
```

AVAILABLE PATTERN IDS (pick the closest match):
{taxonomy_list}

Respond with JSON only."""

README_DAYS_SHOWN = 7
