# OSDC — Technical Documentation

OSDC (Open Source Daily Catch) is an automated patch intelligence system. It scrapes the GitHub Advisory Database, analyzes security fix diffs with a large language model, detects silent patches across high-value repositories using heuristic scoring and fingerprint matching, and publishes everything to a searchable GitHub Pages frontend.

**Live instance:** [christbowel.github.io/OSDC](https://christbowel.github.io/OSDC/)  
**Silent patches:** [christbowel.github.io/OSDC/silent.html](https://christbowel.github.io/OSDC/silent.html)  
**Author:** [Christbowel](https://github.com/Christbowel)  
**Stack:** Python 3.11, Gemini 2.5 Flash, SQLite, GitHub Actions, Jinja2, GitHub Pages


## Table of contents

- [Architecture overview](#architecture-overview)
- [Repository structure](#repository-structure)
- [Advisory pipeline](#advisory-pipeline)
  - [Fetching](#fetching)
  - [Diff filtering](#diff-filtering)
  - [LLM analysis](#llm-analysis)
  - [Pattern taxonomy](#pattern-taxonomy)
  - [Fix quality scoring](#fix-quality-scoring)
  - [State management and checkpointing](#state-management-and-checkpointing)
- [Silent patch detection](#silent-patch-detection)
  - [Overview](#overview)
  - [Layer 1: structural heuristics](#layer-1-structural-heuristics)
  - [Layer 2: fingerprint matching](#layer-2-fingerprint-matching)
  - [Layer 3: manual LLM confirmation](#layer-3-manual-llm-confirmation)
  - [Scoring and normalization](#scoring-and-normalization)
  - [Watchlist](#watchlist)
- [Deep scan](#deep-scan)
- [Fingerprint engine](#fingerprint-engine)
- [Data model](#data-model)
- [Rendering pipeline](#rendering-pipeline)
- [GitHub Actions workflows](#github-actions-workflows)
- [Module reference](#module-reference)
- [Running locally](#running-locally)
- [Configuration reference](#configuration-reference)
- [Extending OSDC](#extending-osdc)
- [Known limitations](#known-limitations)


## Architecture overview

OSDC operates two independent pipelines that feed into a shared frontend.

### Pipeline 1: advisory analysis (3×/day)

```
GitHub Advisory Database (GraphQL)
        │
        ▼
    fetch.py ──── Pull new advisories since last cursor
        │
        ▼
  diff_filter.py ── Remove noise (tests, docs, lockfiles)
        │
        ▼
   analyze.py ──── LLM classification + structured extraction
        │
        ▼
     db.py ──────── SQLite + JSONL append
        │
        ▼
   render.py ────── README, daily patches, GitHub Pages
```

### Pipeline 2: silent patch detection (1×/day)

```
GitHub Events API (245 watchlist repos)
        │
        ▼
  silent_scan.py ── Fetch commits from last 24h
        │
        ▼
  heuristics.py ─── Layer 1: structural scoring (0-100)
        │                     skip merges, bots, CS fixes
        │                     score file paths, code patterns,
        │                     unsafe→safe replacements
        ▼
  fingerprint.py ── Layer 2: match against 28 CWE signatures
        │                     + OSDC live pattern DB
        ▼
  silent_results.jsonl ── Suspects stored for manual review
        │
        ▼
   render.py ────── GitHub Pages silent.html
```

Both pipelines are idempotent. Interrupted runs resume from their last checkpoint.


## Repository structure

```
osdc/
├── .github/
│   └── workflows/
│       ├── daily.yml                Advisory analysis (06:00, 14:00, 23:00 UTC)
│       ├── render.yml               Render pipeline (07:00, 15:00, 00:00 UTC)
│       └── silent_scan.yml          Silent scan (05:30 UTC)
│
├── src/
│   ├── main.py                      Advisory pipeline orchestrator
│   ├── fetch.py                     GitHub Advisory DB queries + diff fetching
│   ├── diff_filter.py               Noise reduction on raw diffs
│   ├── analyze.py                   LLM prompt construction + response parsing
│   ├── db.py                        SQLite lifecycle, JSONL I/O, stats
│   ├── render.py                    Jinja2 rendering for all outputs
│   ├── render_cli.py                Render CLI entry point
│   ├── config.py                    All constants, endpoints, prompts
│   ├── heuristics.py                Layer 1: structural commit scoring
│   ├── fingerprint.py               Layer 2: CWE fingerprint matching
│   ├── fingerprint_builder.py       One-time fingerprint DB generator
│   ├── silent_scan.py               Silent patch scan orchestrator
│   ├── deep_scan.py                 Full repo history scanner
│   ├── backfill_local.py            Ollama-based historical backfill
│   └── backfill.py                  Gemini-based backfill
│
├── data/
│   ├── taxonomy.json                52-pattern closed vulnerability taxonomy
│   ├── patterns.jsonl               Advisory records (source of truth)
│   ├── state.json                   Advisory pipeline cursor
│   ├── watchlist.json               245 repos monitored for silent patches
│   ├── fingerprints.json            CWE + OSDC fingerprint signatures
│   ├── silent_state.json            Silent scan cursor
│   ├── silent_results.jsonl         Silent patch suspects
│   └── deep_scans/                  Per-repo deep scan results
│
├── templates/
│   ├── index.html.j2                GitHub Pages advisory frontend
│   ├── silent.html.j2               GitHub Pages silent patch frontend
│   ├── readme.md.j2                 Auto-generated README
│   └── patch.md.j2                  Daily patch report
│
├── patches/                         Generated daily reports
├── docs/                            GitHub Pages output
├── requirements.txt
├── DOCS.md                          This file
└── README.md                        Auto-generated
```


## Advisory pipeline

### Fetching

OSDC queries the GitHub Advisory Database (GHSA) via GraphQL for advisories published since the last cursor position. Only advisories with a fix commit URL are processed. Advisories without a commit are skipped because the unit of analysis is the fix diff, not the vulnerability description.

Each advisory record includes: `ghsa_id`, `package_name`, `ecosystem`, `language`, `severity`, `cvss_score`, `commit_url`, and `published_at`.

Supported ecosystems: npm, PyPI, Maven, Go, Rust, Packagist, NuGet, RubyGems, and GitHub native reports.

### Diff filtering

Raw diffs contain noise that degrades LLM analysis quality and wastes tokens. `diff_filter.py` applies a multi-stage filter:

**Excluded by default:** test files, documentation, lockfiles (`package-lock.json`, `yarn.lock`, `Cargo.lock`, `poetry.lock`, `go.sum`), build artifacts, changelogs, images, and generated code.

**Override rule:** if a file path contains a security keyword (`auth`, `crypto`, `sanitize`, `permission`, `session`, `csrf`, `xss`, `sql`), it is retained regardless of extension. A file named `auth.test.ts` would normally be excluded but the `auth` keyword keeps it.

**Size cap:** after filtering, the diff is truncated at 500 lines (configurable via `MAX_DIFF_LINES`). If truncated, a `[diff truncated]` marker is appended so the LLM knows the context is incomplete.

### LLM analysis

For every advisory that passes filtering, `analyze.py` builds a structured prompt containing the advisory metadata, filtered diff, and the full 52-pattern taxonomy. The LLM returns a JSON object with classification and extraction fields.

**Prompt structure:**

```
[SYSTEM]   Security vulnerability analyzer. Respond with JSON only.
[TAXONOMY] Full 52-pattern taxonomy injected verbatim.
[ADVISORY] Package, ecosystem, severity, CVSS, publication date.
[DIFF]     Filtered diff (max 500 lines).
[FIELDS]   pattern_id, root_cause, impact, fix_summary, key_diff,
           fix_quality, fix_quality_reason, residual_risk, confidence
```

**Gemini configuration:**

| Parameter | Value | Rationale |
|---|---|---|
| `model` | `gemini-2.5-flash` | Best cost/quality ratio for structured extraction |
| `thinkingBudget` | `0` | CoT disabled; closed taxonomy constrains the reasoning space |
| `maxOutputTokens` | `8192` | Prevents truncated JSON responses |
| `responseMimeType` | `application/json` | Forces structured output |
| `temperature` | `0.2` | Low variance for deterministic classification |

**Fallback chain:** Gemini → Ollama (`qwen2.5-coder:7b`) → `UNCLASSIFIED` stub.

**Response validation:** the parser strips markdown fences, normalizes `key_diff` format (handles Qwen's `{"before":"...","after":"..."}` format), validates `pattern_id` against the taxonomy, and validates `confidence` against the `HIGH/MEDIUM/LOW` enum.

### Pattern taxonomy

The taxonomy is a closed set of 52 vulnerability pattern IDs stored in `data/taxonomy.json`. The LLM must classify every advisory into one of the 52 entries or return `UNCLASSIFIED`. This ensures deterministic cross-run correlation.

Pattern IDs follow the format `VULN_CLASS → IMPACT_CLASS`:

| Pattern ID | Description |
|---|---|
| `SQLI → DATA_EXFIL` | SQL injection leading to data exfiltration |
| `PATH_TRAVERSAL → FILE_WRITE` | Directory traversal leading to arbitrary file write |
| `MISSING_AUTHZ → RESOURCE` | Missing authorization check on a protected resource |
| `XSS → SESSION_HIJACK` | Cross-site scripting enabling session token theft |
| `EVAL_INJECTION → RCE` | Dynamic evaluation of user input leading to code execution |
| `DESERIALIZATION → RCE` | Unsafe deserialization of untrusted data |
| `SSRF → INTERNAL_ACCESS` | Server-side request forgery reaching internal services |

`UNCLASSIFIED` is a valid output. It surfaces advisories that genuinely do not fit any existing pattern and serves as the primary signal for taxonomy expansion.

### Fix quality scoring

Every advisory receives a `fix_quality` assessment extracted by the same LLM call:

| Value | Meaning |
|---|---|
| `GOOD` | Fix fully addresses the root cause. Attack vector closed. |
| `PARTIAL` | Fix reduces attack surface but leaves residual risk. |
| `INCOMPLETE` | Fix is cosmetic or addresses a symptom, not the root cause. |
| `SUSPICIOUS` | Fix appears to weaken a security control or introduce a backdoor. |

Companion fields: `fix_quality_reason` (short explanation) and `residual_risk` (remaining attack vectors).

### State management and checkpointing

`data/state.json` tracks the pipeline cursor:

```json
{
  "last_run_at": "2026-04-15T23:00:00Z",
  "pending_ids": [],
  "today_advisory_count": 34,
  "today_run_number": 3
}
```

**Checkpoint interval:** every 5 advisories, results are flushed to JSONL and state is saved.

**SIGTERM handler:** when GitHub Actions kills a job at timeout, the handler intercepts the signal, flushes the in-memory buffer, updates `pending_ids`, and exits cleanly.

**Recovery flow:** on the next run, IDs in `pending_ids` are refetched and reprocessed. The cursor only advances after a fully successful run.


## Silent patch detection

### Overview

Silent patches are security fixes committed without a public advisory. The maintainer fixes a vulnerability but does not disclose it through CVE, GHSA, or any other channel. This is common in projects that avoid drawing attention to security issues, or where the maintainer does not recognize the security implications of their change.

OSDC detects silent patches through a three-layer funnel that minimizes LLM usage while maximizing detection quality.

### Layer 1: structural heuristics

`src/heuristics.py` scores each commit on structural signals extracted from the diff itself, independent of the commit message. This is pure Python with zero LLM calls.

**Pre-filters (score = 0, skip immediately):**

- Merge commits (`Merge branch`, `Merge pull request`)
- Auto-merge and rollup commits
- Code style fixes (`CS fix`, `prettier`, `eslint`, `rubocop`)
- Translation/i18n changes
- Bot commits (dependabot, renovate, librarian)
- Commits touching > 50 files (bulk refactors)

**Scoring signals:**

| Signal | Weight | Example |
|---|---|---|
| Security file path (HIGH) | 3-5 | `auth.py`, `crypto.go`, `session.js`, `.env`, `.htaccess` |
| Security file path (LOW) | 1-2 | `handler.ts`, `middleware.py`, `parser.rs` |
| Surgical change (1-20 lines) | 3 | Small, targeted fix |
| Added safe function | 3-8 | `hmac.compare_digest`, `PreparedStatement`, `DOMPurify` |
| Removed dangerous function | 3-8 | `eval()`, `exec()`, `innerHTML`, `pickle.load` |
| Unsafe→safe replacement | 3-8 | `MD5→SHA256`, `exec→execFile`, `innerHTML→textContent` |
| Commit message keywords | 1-5 | `fix`, `security`, `sanitize`, `bypass` |

**Multi-language coverage (250+ patterns):**

PHP (`unserialize`, `extract`, `preg_replace /e`, `PDO::prepare`), Java (`Runtime.exec`, `JNDI.lookup`, `PreparedStatement`, `SecureRandom`), Go (`exec.Command`, `filepath.EvalSymlinks`, `filepath.Clean`), Rust (`unsafe{}`, `transmute`, `MaybeUninit`), Python (`pickle.load`, `subprocess.run`, `secrets.token`), C/C++ (`strcpy`, `gets`, `sprintf`, `snprintf`), JavaScript/Node (`eval`, `Function()`, `child_process.exec`, `DOMPurify`).

**Normalization:** raw scores are normalized to 0-100. Maximum 5 files scored per commit, maximum 15 points per file. Threshold for passing to Layer 2: score ≥ 12.

### Layer 2: fingerprint matching

`src/fingerprint.py` compares the diff tokens of a suspect commit against a database of known vulnerability fix signatures.

**Fingerprint sources:**

- 28 expert-curated CWE fingerprints covering XSS, SQLi, command injection, path traversal, CSRF, auth bypass, SSRF, deserialization, weak crypto, race conditions, and more
- OSDC live advisory data (growing daily)

**Matching algorithm:** Jaccard similarity on tokenized added/removed lines. Weighted score: 40% add similarity + 30% delete similarity + 30% overall similarity.

**Token extraction:** identifiers are split by dots and camelCase boundaries. Noise tokens (common language keywords) are filtered. Tokens shorter than 3 characters are discarded.

### Layer 3: manual LLM confirmation

Layer 3 is intentionally not automated. The operator reviews the top suspects from Layers 1+2 and runs targeted LLM analysis on selected commits using a local model (Ollama) or a more powerful cloud model. This keeps costs at zero while maintaining high precision on confirmed findings.

### Scoring and normalization

The final score displayed on the frontend combines both layers:

```
normalized = heuristic_normalized + (fingerprint_score × 30)
```

Capped at 100. Score interpretation:

| Range | Label | Meaning |
|---|---|---|
| 60-100 | HIGH | Strong security signals, likely a real silent fix |
| 30-59 | MEDIUM | Multiple signals present, worth investigating |
| 15-29 | LOW | Weak signals, likely noise or hardening |

### Watchlist

`data/watchlist.json` contains ~245 high-value repositories organized by attack surface:

- **Web frameworks:** Express, Django, Flask, FastAPI, Rails, Laravel, Spring, Next.js, Nuxt
- **Crypto/TLS:** OpenSSL, BoringSSL, wolfSSL, mbedTLS, libsodium
- **Runtimes:** Node.js, CPython, Ruby, PHP, Go, Rust, Deno
- **Infrastructure:** Kubernetes, Docker, containerd, Envoy, Traefik, Nginx
- **Databases:** PostgreSQL, MySQL, Redis, MongoDB, Elasticsearch
- **Auth:** Keycloak, Passport, NextAuth, Authelia, Casdoor
- **CMS:** WordPress, Drupal, Ghost, Directus, Strapi

To add a repo, append its `owner/repo` string to the `repos` array in `data/watchlist.json`.


## Deep scan

`src/deep_scan.py` scans the full commit history of a specific repository. It is designed for targeted investigation of high-interest repos and runs locally on the operator's machine.

**Usage:**

```bash
export GITHUB_TOKEN=your_token

# Scan all commits since a date
python -m src.deep_scan openssl/openssl --since 2025-01-01

# Scan a specific date range
python -m src.deep_scan axios/axios --since 2024-06-01 --until 2025-01-01

# Limit commit count
python -m src.deep_scan torvalds/linux --since 2025-01-01 --max 500
```

**Features:**

- Automatic rate limit handling with wait-and-retry
- Incremental: skips already-scanned commits on re-runs
- Results saved to `data/deep_scans/{owner}_{repo}.jsonl`
- Top suspects displayed at the end with score and signals

**Merging results into the main database:**

```bash
cat data/deep_scans/openssl_openssl.jsonl >> data/silent_results.jsonl
```


## Fingerprint engine

### Building fingerprints

`src/fingerprint_builder.py` generates `data/fingerprints.json` from two sources:

1. **Expert-curated CWE signatures** (28 patterns): hand-picked tokens for XSS, SQLi, command injection, path traversal, CSRF, auth bypass, SSRF, open redirect, deserialization, weak crypto, weak random, race conditions, resource exhaustion, XXE, integer overflow, use-after-free, null deref, missing authz, hardcoded credentials, prototype pollution, info disclosure, missing signature check, unrestricted upload, code injection, improper cert validation, ReDoS, privilege escalation, resource allocation.

2. **OSDC live data** from `data/patterns.jsonl`: tokens extracted from real CVE fix diffs, grouped by pattern ID.

```bash
python -m src.fingerprint_builder
```

This is a one-time operation. The generated `data/fingerprints.json` is committed to the repo. As the advisory database grows, re-running the builder enriches the fingerprints with new real-world data.

### Matching

For each suspect commit, `fingerprint.py` tokenizes the diff, computes Jaccard similarity against every fingerprint in the database, and returns the top 5 matches with scores. A match score ≥ 0.1 is considered significant.


## Data model

### Advisory record (`data/patterns.jsonl`)

```json
{
  "ghsa_id": "GHSA-3p68-rc4w-qgx5",
  "package_name": "axios",
  "ecosystem": "npm",
  "language": "JavaScript",
  "severity": "HIGH",
  "cvss_score": 7.5,
  "commit_url": "https://github.com/axios/axios/commit/abc123",
  "published_at": "2026-04-13T06:00:00Z",
  "analyzed_at": "2026-04-13T07:14:22Z",
  "pattern_id": "PATH_TRAVERSAL -> FILE_WRITE",
  "root_cause": "URL normalization bypassed by ../ sequences in redirect targets",
  "impact": "SSRF and open redirect enabling exfiltration of internal resources",
  "fix_summary": "Strict host validation applied before following redirects",
  "key_diff": "- if (url.startsWith('/'))\n+ if (isAbsoluteURL(url) && isSameOrigin(url))",
  "fix_quality": "GOOD",
  "fix_quality_reason": "Validates full URL structure before following",
  "residual_risk": "None identified",
  "confidence": "HIGH",
  "run_number": 1
}
```

### Silent patch suspect (`data/silent_results.jsonl`)

```json
{
  "commit_sha": "f45bb996...",
  "repo": "openssl/openssl",
  "commit_url": "https://github.com/openssl/openssl/commit/f45bb996",
  "message": "Precompute some helper objects in each SSL_CTX",
  "date": "2026-04-07T14:22:00Z",
  "author": "Viktor Dukhovni",
  "normalized_score": 62.5,
  "heuristic_score": 50,
  "heuristic_normalized": 62.5,
  "top_file": "ssl/ssl_lib.c",
  "top_file_score": 15,
  "top_file_signals": ["sec_file:ssl[._/]", "moderate", "+hmac", "-md5", "-sha1", "swap:MD5→SHA256"],
  "fingerprint_match": null,
  "fingerprint_score": 0.0,
  "files_changed": 7,
  "status": "SUSPECT"
}
```

### SQLite schema

```sql
CREATE TABLE advisories (
  ghsa_id             TEXT PRIMARY KEY,
  package_name        TEXT NOT NULL,
  ecosystem           TEXT NOT NULL,
  language            TEXT NOT NULL,
  severity            TEXT NOT NULL,
  cvss_score          REAL,
  commit_url          TEXT,
  published_at        TEXT NOT NULL,
  analyzed_at         TEXT NOT NULL,
  pattern_id          TEXT NOT NULL DEFAULT 'UNCLASSIFIED',
  root_cause          TEXT NOT NULL DEFAULT '',
  impact              TEXT NOT NULL DEFAULT '',
  fix_summary         TEXT NOT NULL DEFAULT '',
  key_diff            TEXT NOT NULL DEFAULT '',
  fix_quality         TEXT NOT NULL DEFAULT '',
  fix_quality_reason  TEXT NOT NULL DEFAULT '',
  residual_risk       TEXT NOT NULL DEFAULT '',
  run_number          INTEGER NOT NULL DEFAULT 1
);
```

The SQLite database is rebuilt from JSONL on every run and is never committed to git.


## Rendering pipeline

### Output files

| File | Template | Updated by |
|---|---|---|
| `patches/YYYY-MM-DD.md` | `patch.md.j2` | render workflow |
| `README.md` | `readme.md.j2` | render workflow |
| `docs/index.html` | `index.html.j2` | render workflow |
| `docs/silent.html` | `silent.html.j2` | render workflow |
| `docs/search-index.json` | inline | render workflow |
| `docs/badge-advisories.json` | inline | render workflow |
| `docs/badge-patterns.json` | inline | render workflow |

### GitHub Pages frontend

Single-file applications with zero build step, no framework, no server-side dependencies.

**Advisory page (`index.html`):**
- Card grid with severity badges, language tags, pattern IDs
- Fix quality indicators for PARTIAL and INCOMPLETE fixes
- Chart.js dashboard: severity distribution, top patterns, language breakdown, timeline
- Client-side full-text search
- Light/dark mode toggle

**Silent patch page (`silent.html`):**
- Suspects ranked by normalized score (0-100)
- Score badges: HIGH (≥60, red), MEDIUM (≥30, orange), LOW (<30, yellow)
- Expandable cards with score breakdown, detection signals, diff samples
- Fingerprint match display with matched tokens
- Search and score filtering


## GitHub Actions workflows

### `daily.yml` — advisory analysis

```yaml
schedule:
  - cron: '0 6 * * *'     # Run 1
  - cron: '0 14 * * *'    # Run 2
  - cron: '0 23 * * *'    # Run 3
```

Requires secret: `GEMINI_API_KEY`

### `render.yml` — render pipeline

```yaml
schedule:
  - cron: '0 7 * * *'
  - cron: '0 15 * * *'
  - cron: '0 0 * * *'
```

### `silent_scan.yml` — silent patch scan

```yaml
schedule:
  - cron: '30 5 * * *'    # Daily at 05:30 UTC
```

Timeout: 45 minutes. Uses `GITHUB_TOKEN` (auto-provided).


## Module reference

| Module | Purpose |
|---|---|
| `main.py` | Advisory pipeline orchestrator with SIGTERM handler |
| `fetch.py` | GHSA GraphQL queries, commit diff fetching |
| `diff_filter.py` | Noise reduction on raw diffs |
| `analyze.py` | LLM prompt construction, response parsing, fallback chain |
| `db.py` | SQLite rebuild, JSONL I/O, stats queries |
| `config.py` | All constants, endpoints, prompts, file paths |
| `render.py` | Jinja2 rendering for all output formats |
| `render_cli.py` | CLI entry point for the render pipeline |
| `heuristics.py` | Layer 1 structural scoring engine (250+ patterns) |
| `fingerprint.py` | Layer 2 CWE fingerprint matching (Jaccard similarity) |
| `fingerprint_builder.py` | One-time fingerprint DB generator |
| `silent_scan.py` | Daily silent patch scan orchestrator |
| `deep_scan.py` | Full repo history scanner with rate limit handling |
| `backfill_local.py` | Historical backfill via Ollama (qwen2.5-coder:7b) |
| `backfill.py` | Historical backfill via Gemini |


## Running locally

### Advisory pipeline

```bash
export GEMINI_API_KEY=your_key
python -m src.main
```

### Silent patch scan

```bash
export GITHUB_TOKEN=your_token
python -m src.silent_scan          # last 24h
python -m src.silent_scan 48       # last 48h
```

### Deep scan a specific repo

```bash
export GITHUB_TOKEN=your_token
python -m src.deep_scan owner/repo --since 2025-01-01
```

### Build fingerprints

```bash
python -m src.fingerprint_builder
```

### Backfill with Ollama

```bash
python -m src.backfill_local 30    # last 30 days
```

### Force re-render

```bash
python -m src.render_cli
```

### Inspect statistics

```bash
python -c "
from src.db import rebuild_from_jsonl, get_stats
import json
rebuild_from_jsonl()
print(json.dumps(get_stats(), indent=2))
"
```


## Configuration reference

All values defined in `src/config.py`.

### LLM

| Constant | Default | Description |
|---|---|---|
| `GEMINI_MODEL` | `gemini-2.5-flash` | Primary LLM |
| `GEMINI_THINKING_BUDGET` | `0` | CoT disabled |
| `GEMINI_MAX_OUTPUT_TOKENS` | `8192` | Response size cap |
| `OLLAMA_MODEL` | `qwen2.5-coder:7b` | Local fallback |

### Pipeline

| Constant | Default | Description |
|---|---|---|
| `CHECKPOINT_INTERVAL` | `5` | Flush every N advisories |
| `MAX_DIFF_LINES` | `500` | Diff truncation limit |
| `MAX_ADVISORIES_PER_RUN` | `50` | Safety cap per cron |

### Silent scan

| Constant | Default | Description |
|---|---|---|
| `THRESHOLD` | `12` | Minimum heuristic score |
| `MAX_FILES_SCORED` | `5` | Max files contributing to score |
| `MAX_SCORE_PER_FILE` | `15` | Per-file score cap |
| `MAX_TOTAL_FILES` | `50` | Skip commits above this |
| `REQUEST_DELAY` | `0.8s` | Delay between API calls |


## Extending OSDC

### Adding a repo to the watchlist

Append the `owner/repo` string to `data/watchlist.json`:

```json
{
  "repos": [
    "existing/repo",
    "new-owner/new-repo"
  ]
}
```

### Adding a taxonomy pattern

Edit `data/taxonomy.json`:

```json
{
  "TEMPLATE_INJECTION -> RCE": "Server-side template injection leading to code execution"
}
```

No code changes needed. The LLM uses new patterns from the next run.

### Adding detection patterns

Edit `src/heuristics.py`. Add entries to `ADD_PATTERNS` (safe functions to detect), `DEL_PATTERNS` (dangerous functions), or `REPLACEMENT_PAIRS` (unsafe→safe transitions):

```python
ADD_PATTERNS = {
    r"\bmy_safe_function\b": 5,
}

DEL_PATTERNS = {
    r"\bmy_dangerous_function\b": 6,
}

REPLACEMENT_PAIRS = [
    (r"\bdangerous\b", r"\bsafe\b", 7),
]
```

### Adding a new LLM provider

Add a call function in `analyze.py` and insert it in the fallback chain:

```python
def _call_myprovider(prompt: str) -> dict | None:
    ...

# In analyze_advisory():
result = _call_gemini(prompt) or _call_myprovider(prompt) or _call_ollama(prompt)
```

### Adding a new output format

1. Create a Jinja2 template in `templates/`
2. Add a render function in `render.py`
3. Call it from `render_cli.py`


## Known limitations

**UNCLASSIFIED rate with Ollama.** `qwen2.5-coder:7b` has weaker taxonomy adherence than Gemini. Runs falling back to Ollama produce more UNCLASSIFIED records. Reprocess with `backfill.py` once Gemini quota resets.

**GHSA coverage gaps.** Strong for npm, PyPI, Go. Weaker for C/C++, firmware, and proprietary ecosystems. Advisories without a fix commit are skipped entirely.

**Silent patch false positives.** Layers 1+2 optimize for recall over precision. Expect ~70% of suspects to be noise (refactors, feature additions that happen to touch security-relevant files). Layer 3 (manual review) is required to confirm findings.

**GitHub API rate limits.** 5,000 requests/hour with `GITHUB_TOKEN`. The silent scan includes wait-and-retry logic on rate limit exhaustion. Deep scans on large repos (10,000+ commits) may take several hours due to rate limit pauses.

**No cross-commit deduplication.** A commit fixing multiple vulnerabilities generates multiple records. This is visually redundant but does not corrupt the database.

**Fingerprint DB coverage.** Currently 28 CWE patterns + OSDC live data. Coverage improves as the advisory database grows. PatchDB (12K patches from George Mason University) can be integrated when access is approved.
