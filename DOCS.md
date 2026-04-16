# OSDC Technical Documentation

OSDC (Open Source Daily Catch) is an automated patch intelligence system. It scrapes the GitHub Advisory Database three times a day, analyzes security fix diffs with a large language model, correlates vulnerabilities across ecosystems using a closed taxonomy, and publishes the results to a searchable GitHub Pages site.

**Live instance:** https://christbowel.github.io/OSDC/
**Author:** Christbowel
**Stack:** Python 3.11 / Gemini 2.5 Flash / SQLite / GitHub Actions / Jinja2 / GitHub Pages


## Table of Contents

- [Architecture overview](#architecture-overview)
- [Repository structure](#repository-structure)
- [Core concepts](#core-concepts)
  - [Advisory processing](#advisory-processing)
  - [Diff filtering](#diff-filtering)
  - [Pattern taxonomy](#pattern-taxonomy)
  - [LLM analysis pipeline](#llm-analysis-pipeline)
  - [Fix quality scoring](#fix-quality-scoring)
  - [Silent patch detection](#silent-patch-detection)
  - [State management and checkpointing](#state-management-and-checkpointing)
- [Data flow](#data-flow)
- [Module reference](#module-reference)
- [Data model](#data-model)
- [GitHub Actions workflows](#github-actions-workflows)
- [Rendering pipeline](#rendering-pipeline)
- [Deployment](#deployment)
- [Running locally](#running-locally)
- [Configuration reference](#configuration-reference)
- [Extending OSDC](#extending-osdc)
- [Known limitations](#known-limitations)


## Architecture overview

Each run follows a linear pipeline. There is no branching logic at the orchestration level: every advisory either completes all stages successfully or is checkpointed for retry on the next run.

```
GitHub Advisory Database
        |
        v
    fetch.py          Pull new advisories since last cursor position
        |
        v
  diff_filter.py      Remove noise (tests, docs, lock files, build artifacts)
        |
        v
    analyze.py        LLM analysis: pattern classification and structured extraction
        |
        v
      db.py           Write to SQLite and append to JSONL source of truth
        |
        v
    render.py         Generate daily Markdown, README, GitHub Pages frontend
        |
        v
  GitHub Actions      Commit and push all changes, deploy Pages
```

Three cron jobs run daily at 06:00, 14:00, and 23:00 UTC. Each is independent and idempotent. The `state.json` cursor ensures no advisory is processed twice and that interrupted runs resume from their last checkpoint.


## Repository structure

```
osdc/
  .github/
    workflows/
      daily.yml               Cron automation and GitHub Pages deployment

  src/
    main.py                   Orchestrator: drives the full pipeline per run
    fetch.py                  GitHub Advisory Database GraphQL queries and diff fetching
    diff_filter.py            Noise reduction: filters diffs to security-relevant hunks
    analyze.py                LLM integration: prompt construction, response parsing, pattern matching
    db.py                     SQLite lifecycle, JSONL read/write, stats queries
    render.py                 Jinja2 rendering for all output formats
    backfill.py               Historical backfill with Ollama fallback for rate-limit recovery
    config.py                 All constants, endpoints, LLM parameters, extension lists

  data/
    taxonomy.json             Closed 52-pattern vulnerability taxonomy
    patterns.jsonl            Append-only advisory record (source of truth, git-tracked)
    state.json                Run cursor: last timestamp, pending IDs, run counter

  templates/
    patch.md.j2               Daily report template
    readme.md.j2              Auto-generated README template
    index.html.j2             GitHub Pages searchable frontend

  patches/                    Generated daily Markdown reports (git-tracked)
  docs/                       Generated GitHub Pages output (index.html and search-index.json)

  requirements.txt            requests, jinja2
  README.md                   Auto-generated on each run
```


## Core concepts

### Advisory processing

An advisory is a record published to the GitHub Advisory Database (GHSA) describing a known vulnerability in an open source package. GHSA aggregates reports from npm, PyPI, Maven, Go, Rust, Packagist, NuGet, RubyGems, and native GitHub security reports.

OSDC only processes advisories that include a reference to a fix commit. Advisories without a commit URL are skipped because without a diff there is nothing to analyze. This is a deliberate design choice: the unit of analysis is the fix, not the vulnerability description.

Each advisory goes through the following lifecycle:

1. **Fetched** from GHSA GraphQL API, filtered by publication date using the `last_run_at` cursor
2. **Diff retrieved** via the GitHub REST API using the commit URL embedded in the advisory
3. **Diff filtered** to remove files irrelevant to the security fix
4. **Analyzed** by the LLM, which extracts a structured record including pattern ID, root cause, impact, fix summary, key diff lines, and fix quality
5. **Persisted** to SQLite and appended to `data/patterns.jsonl`
6. **Rendered** into the daily report and GitHub Pages frontend

The `ghsa_id` field is the primary key. If an advisory is already present in the JSONL, it is skipped on subsequent runs.

### Diff filtering

Raw git diffs contain significant noise that degrades LLM analysis quality and wastes context tokens. The `diff_filter.py` module removes this noise before any advisory reaches the LLM.

**What gets removed**

Test files are excluded because they rarely contain the security-critical logic and frequently include intentional examples of bad input. Documentation files are excluded because they describe the fix rather than implement it. Lock files, build artifacts, changelogs, and generated files are excluded because they contain no source logic.

The full exclusion list covers extensions including `.md`, `.rst`, `.txt`, `.lock`, `.sum`, `.png`, `.jpg`, `.svg`, `package-lock.json`, `yarn.lock`, `Cargo.lock`, `poetry.lock`, and others defined in `config.EXCLUDED_EXTENSIONS`.

**Override logic**

If a file path contains one of the security-relevant keywords defined in `config.SECURITY_KEYWORDS` (such as `auth`, `crypto`, `sanitize`, `permission`, `session`, `csrf`, `xss`, `sql`), it is retained regardless of its extension. A file named `auth.test.ts` would normally be excluded as a test file, but the `auth` keyword causes it to be kept.

**Size cap**

After filtering, the diff is truncated at `MAX_DIFF_LINES` (default 500 lines) to stay within the LLM context window. Truncation is applied from the bottom of the diff, preserving the earliest and typically most security-relevant changes.

### Pattern taxonomy

The taxonomy is the core intellectual asset of OSDC. It is a closed set of 52 vulnerability pattern IDs stored in `data/taxonomy.json`. The LLM cannot invent new patterns: it must classify every advisory into one of the 52 entries or return `UNCLASSIFIED`.

Pattern IDs follow the format `VULN_CLASS -> IMPACT_CLASS`. Examples:

| Pattern ID | Description |
|---|---|
| `SQLI -> DATA_EXFIL` | SQL injection leading to data exfiltration |
| `PATH_TRAVERSAL -> FILE_WRITE` | Directory traversal leading to arbitrary file write |
| `MISSING_AUTHZ -> RESOURCE` | Missing authorization check on a protected resource |
| `XSS -> SESSION_HIJACK` | Cross-site scripting enabling session token theft |
| `EVAL_INJECTION -> RCE` | Dynamic evaluation of user-controlled input leading to code execution |
| `CSRF -> STATE_MUTATION` | Cross-site request forgery mutating server state |
| `SSRF -> INTERNAL_ACCESS` | Server-side request forgery reaching internal services |
| `RACE_CONDITION -> PRIV_ESC` | Race condition exploitable for privilege escalation |
| `DESERIALIZATION -> RCE` | Unsafe deserialization of untrusted data |
| `OPEN_REDIRECT -> PHISHING` | Unvalidated redirect used for phishing or credential harvesting |

The taxonomy is injected verbatim into every LLM prompt. The model has the full classification context at inference time and does not rely on training-time knowledge of the taxonomy structure.

**Why a closed taxonomy matters**

Open taxonomies produce inconsistent labels across runs. The same vulnerability pattern might be labeled `SQL injection`, `SQLi`, `database injection`, or `unsanitized query` depending on the run. This makes cross-run correlation impossible. The closed taxonomy trades flexibility for determinism: every `SQLI -> DATA_EXFIL` record across the entire history refers to the same class of vulnerability.

`UNCLASSIFIED` is a valid and expected value. It surfaces advisories that genuinely do not fit any existing pattern and serves as the primary signal for identifying candidates for taxonomy expansion.

### LLM analysis pipeline

The LLM analysis stage is the most compute-intensive part of each run. For every advisory that passes filtering, `analyze.py` builds a prompt, calls the Gemini API, and parses the JSON response.

**Prompt structure**

```
[SYSTEM]
You are a security vulnerability analyzer.
Respond with a single JSON object. No preamble. No markdown fences.

[TAXONOMY]
<full 52-pattern taxonomy>

[ADVISORY]
Package: {package_name} ({ecosystem})
Severity: {severity} / CVSS: {cvss_score}
Published: {published_at}

[DIFF]
{filtered_diff}

[INSTRUCTION]
Analyze the fix. Return JSON with fields:
pattern_id, root_cause, impact, fix_summary, key_diff,
fix_quality, fix_quality_reason, residual_risk
```

**Gemini configuration**

```python
model = "gemini-2.5-flash"
generation_config = {
    "thinkingBudget": 0,
    "maxOutputTokens": 8192,
    "responseMimeType": "application/json"
}
```

`thinkingBudget: 0` disables chain-of-thought reasoning. For structured extraction from a known format with a constrained output space, CoT adds latency without improving accuracy. The closed taxonomy already constrains the reasoning space at the prompt level.

**Fallback chain**

1. Gemini API (primary)
2. Ollama local endpoint with `qwen2.5-coder:7b` on Gemini quota error or connection failure
3. `UNCLASSIFIED` stub record if both fail

**Response parsing**

The response is expected to be a raw JSON object. The parser strips any accidental markdown fences, handles `key_diff` field normalization (Qwen occasionally returns a `{"before": "...", "after": "..."}` object instead of a diff string), and validates that `pattern_id` is a member of the taxonomy. An invalid `pattern_id` is replaced with `UNCLASSIFIED` rather than raising an error.

### Fix quality scoring

Every advisory analyzed by OSDC receives a `fix_quality` assessment. This is not a post-hoc annotation: it is extracted by the same LLM call that classifies the pattern, using the same diff context.

**Quality levels**

| Value | Meaning |
|---|---|
| `GOOD` | The fix fully addresses the root cause. The attack vector is closed. |
| `PARTIAL` | The fix reduces the attack surface but leaves residual risk. Common for fixes that sanitize output without addressing input validation, or that add a check in one code path but not all equivalent paths. |
| `INCOMPLETE` | The fix is cosmetic, ineffective, or addresses a symptom rather than the root cause. The vulnerability is likely still exploitable in a modified form. |
| `SUSPICIOUS` | The fix appears to intentionally weaken a security control, introduce a backdoor condition, or bypass an existing guard. |

The LLM also produces two companion fields: `fix_quality_reason` (a short explanation of the assessment) and `residual_risk` (a description of attack vectors that remain open after the fix).

**Why this matters**

A significant fraction of published CVE fixes are partial or incomplete. Maintainers under pressure to close an advisory often fix the reported reproduction case without addressing the underlying class of vulnerability. OSDC surfaces these cases. A `PARTIAL` rating on a widely-deployed package is a higher-value signal than a `GOOD` rating on a niche library.

The `SUSPICIOUS` category is gated on strong evidence in the diff. The LLM prompt explicitly instructs the model to only use this rating when there is direct evidence in the changed code, not based on inference about maintainer intent.

### Silent patch detection

Silent patches are security fixes committed to a repository without a corresponding public advisory. The maintainer fixes the vulnerability but does not disclose it through CVE, GHSA, or any other advisory channel. This is common in projects that prefer to avoid drawing attention to security issues, or where the maintainer does not recognize that their fix has security implications.

OSDC addresses silent patches through a second detection workflow that operates independently of the advisory pipeline.

**Detection mechanism**

The silent patch detector monitors the GitHub Events API for commit activity on a curated list of repositories. For each commit, it applies a two-stage filter.

Stage one uses commit message heuristics. Commits whose message contains keywords associated with security fixes (`fix`, `security`, `sanitize`, `vulnerability`, `patch`, `prevent`, `escape`, `validate`, `bypass`) but do not reference an advisory ID (no `GHSA-`, `CVE-`, `#advisory`) are flagged as candidates.

Stage two uses LLM classification. Candidate commits are sent through the same diff filter and LLM analysis pipeline as advisory-sourced commits. The LLM is asked whether this is a security fix, and if so, to classify it using the taxonomy and assign a confidence level.

Commits where the LLM returns confidence `HIGH` are stored with a `SUSPECTED_SILENT_FIX` flag in a dedicated table and displayed separately on the GitHub Pages frontend.

**Confidence scoring**

The LLM produces a confidence value (`HIGH`, `MEDIUM`, `LOW`) based on the specificity of the diff. A diff that adds input validation, fixes a format string, removes an `eval()` call, or patches a cryptographic operation in a security-relevant file receives `HIGH` confidence. A diff that renames a variable and happens to contain the word `fix` in the commit message receives `LOW` confidence and is not surfaced.

**Relationship to the heuristic scoring system**

The heuristic scoring system (commit message analysis, surgical signal detection, fingerprint matching) operates upstream of the LLM classification step. It generates a ranked list of candidate commits. OSDC's LLM pipeline consumes the top-ranked candidates and produces structured records. The two systems are complementary: the scorer provides recall on detection, the LLM provides structured intelligence on classification.

**Why the database needs to reach a minimum size first**

Silent patch detection works best when the taxonomy classification is well-calibrated against real-world data. Calibration improves as more advisories accumulate because the LLM has more in-context reference material when assigning confidence levels. The recommended threshold before enabling the silent patch workflow is 500 analyzed advisories.

### State management and checkpointing

OSDC uses a file-based state machine to ensure that interrupted runs do not result in lost work or duplicate processing.

**`data/state.json` fields**

```json
{
  "last_run_at": "2026-04-15T23:00:00Z",
  "pending_ids": [],
  "today_advisory_count": 34,
  "today_run_number": 3
}
```

`last_run_at` is the primary cursor. Every advisory fetch query uses this timestamp as the lower bound. It is only updated after a successful run completion.

`pending_ids` holds advisory IDs that were fetched in the current run but have not yet been committed to the JSONL. If the process is interrupted, these IDs are in an uncertain state. On the next run, IDs present in `pending_ids` are re-fetched and reprocessed from scratch.

**Checkpoint interval**

Every 5 advisories, the current results are flushed to `data/patterns.jsonl` and `state.json` is saved. This bounds the maximum rework on failure to 5 advisories regardless of when the interruption occurs.

**SIGTERM handler**

A SIGTERM handler is registered before the analysis loop begins. When GitHub Actions kills a job that exceeds its timeout, the handler intercepts the signal, flushes the current in-memory buffer to JSONL, updates `pending_ids`, and exits cleanly. This prevents silent data loss on timeout.

**Normal flow vs recovery flow**

In a normal run: fetch advisories since `last_run_at`, process all, update cursor to now, clear `pending_ids`.

In a recovery run: fetch advisories since `last_run_at` (same window as the interrupted run), skip IDs already present in the JSONL, reprocess IDs in `pending_ids`, continue with remaining IDs. The cursor does not advance until the full run completes successfully.


## Data flow

```
GitHub Advisory Database (GraphQL API)
  |
  | ghsa_id, package, severity, cvss, commit_url, published_at
  v
fetch.py
  |
  | raw unified diff
  v
diff_filter.py
  |
  | filtered diff (security-relevant files only, capped at MAX_DIFF_LINES)
  v
analyze.py
  |
  | pattern_id, root_cause, impact, fix_summary, key_diff,
  | fix_quality, fix_quality_reason, residual_risk
  v
db.py
  |
  +-- SQLite (runtime index, rebuilt from JSONL each run, not committed)
  +-- data/patterns.jsonl (source of truth, git-tracked, append-only)
  |
  v
render.py
  |
  +-- patches/YYYY-MM-DD.md
  +-- README.md
  +-- docs/index.html
  +-- docs/search-index.json
```


## Module reference

### `src/config.py`

Central configuration. All tunable constants are defined here. No module defines magic values inline.

| Constant | Default | Description |
|---|---|---|
| `GEMINI_MODEL` | `gemini-2.5-flash` | Primary LLM |
| `GEMINI_THINKING_BUDGET` | `0` | Disables CoT for latency |
| `GEMINI_MAX_OUTPUT_TOKENS` | `8192` | Response size cap |
| `OLLAMA_MODEL` | `qwen2.5-coder:7b` | Local fallback model |
| `CHECKPOINT_INTERVAL` | `5` | Flush to JSONL every N advisories |
| `MAX_DIFF_LINES` | `500` | Diff truncation limit |
| `MAX_ADVISORIES_PER_RUN` | `50` | Safety cap per cron execution |

### `src/fetch.py`

Handles all external HTTP calls to GitHub.

**`fetch_advisories(since: str) -> list[dict]`**

Queries the GitHub Advisory Database GraphQL API for all advisories published after the `since` timestamp (ISO 8601). Paginates automatically using the `endCursor` field. Returns a flat list of advisory dicts, each containing `ghsa_id`, `package_name`, `ecosystem`, `language`, `severity`, `cvss_score`, `commit_url`, and `published_at`.

**`fetch_commit_diff(commit_url: str) -> str`**

Fetches the raw unified diff for a commit via the GitHub REST API. Appends `.diff` to the commit URL to request the raw diff format. Returns an empty string on 404, 403, or rate-limit responses. Does not raise on errors: a missing diff results in the advisory being stored with an empty diff field.

### `src/diff_filter.py`

**`filter_diff(raw_diff: str) -> str`**

Applies the exclusion rules described in [Diff filtering](#diff-filtering). Returns a filtered unified diff string. If the filtered result is empty (all files excluded), returns an empty string, which causes the analysis step to be skipped for that advisory.

### `src/analyze.py`

**`analyze_advisory(advisory: dict, filtered_diff: str) -> dict`**

Builds the prompt from advisory metadata, the filtered diff, and the full taxonomy. Calls Gemini. Parses and validates the JSON response. Returns a complete advisory record dict ready for insertion into the database.

**`load_taxonomy() -> dict`**

Reads `data/taxonomy.json` and returns the pattern registry as a dict mapping pattern IDs to descriptions.

**`_call_gemini(prompt: str) -> dict | None`**

Internal. Calls the Gemini API with configured parameters. Returns a parsed JSON dict or None on failure.

**`_call_ollama(prompt: str) -> dict | None`**

Internal. Calls the local Ollama endpoint. Same return contract as `_call_gemini`. Used as fallback when Gemini is unavailable or quota-exhausted.

### `src/db.py`

**`rebuild_from_jsonl()`**

Drops and recreates the SQLite schema, then replays every line from `data/patterns.jsonl`. Called once at the start of each run. Ensures SQLite is always a deterministic projection of the JSONL file.

**`insert_advisory(record: dict)`**

Inserts a record into SQLite and appends it to `data/patterns.jsonl`. The JSONL append is atomic: the new line is written to a temp file and renamed into place to prevent partial writes.

**`get_stats() -> dict`**

Returns aggregate statistics: `total_advisories`, `total_patterns`, `by_severity`, `by_language`, `top_patterns`. Used by the render step for the dashboard and README.

**`export_to_jsonl()`**

Re-exports the full SQLite content to `data/patterns.jsonl`. Used after backfill runs to normalize the file.

### `src/render.py`

**`render_all(date: str)`**

Queries SQLite for all advisories and renders the full set of output files. Called once per run after all advisories have been analyzed and persisted.

**`_clean_diff(raw: str) -> str`**

Internal. Normalizes the `key_diff` field. Handles plain diff strings, JSON objects `{"before": "...", "after": "..."}` produced by Qwen, markdown code fences, and null/empty values. Always returns a plain string suitable for display.

### `src/backfill.py`

**`backfill(start_date: str, end_date: str)`**

Fetches and analyzes advisories for a historical date range using Ollama locally to avoid consuming Gemini quota. Intended for manual execution on a machine with Ollama installed, not in GitHub Actions. Typical use: populate 30-60 days of history on a fresh deployment before the daily crons take over.

### `src/main.py`

**`run()`**

Top-level entry point. Reads `RUN_NUMBER` from the environment. Registers the SIGTERM handler. Drives the pipeline: `rebuild_from_jsonl -> load_state -> fetch_advisories -> filter and analyze loop with checkpointing -> render_all -> save_state`. Returns a commit message string summarizing the run.


## Data model

### Advisory record

Every advisory is stored as a single JSON object in `data/patterns.jsonl` (one object per line) and as a row in the SQLite `advisories` table.

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
  "fix_quality_reason": "The fix validates the full URL structure before following, closing the traversal path",
  "residual_risk": "None identified in this diff",
  "run_number": 1
}
```

### `data/state.json`

```json
{
  "last_run_at": "2026-04-15T23:00:00Z",
  "pending_ids": [],
  "today_advisory_count": 34,
  "today_run_number": 3
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

CREATE INDEX idx_pattern_id ON advisories(pattern_id);
CREATE INDEX idx_published_at ON advisories(published_at);
CREATE INDEX idx_severity ON advisories(severity);
```

The SQLite database is rebuilt from `data/patterns.jsonl` on every run and is never committed to git.


## GitHub Actions workflows

### `.github/workflows/daily.yml`

```yaml
on:
  schedule:
    - cron: '0 6 * * *'     # Run 1
    - cron: '0 14 * * *'    # Run 2
    - cron: '0 23 * * *'    # Run 3
  workflow_dispatch:
```

The `RUN_NUMBER` environment variable is injected per-trigger (1, 2, or 3) and is embedded in advisory records and commit messages for traceability.

**Job steps**

1. Checkout with full history (required to read `state.json` reliably)
2. Set up Python 3.11
3. `pip install -r requirements.txt`
4. `python -m src.main` with `GEMINI_API_KEY` from GitHub Secrets
5. `git add -A && git commit -m "feat: patch analysis {date} [{run}/3] - {n} advisories, {p} new patterns"`
6. `git push`
7. GitHub Pages deployment from `docs/` folder

**Required secrets**

| Secret | Description |
|---|---|
| `GEMINI_API_KEY` | Gemini API key from Google AI Studio |
| `GITHUB_TOKEN` | Automatically provided by GitHub Actions |


## Rendering pipeline

### Output files per run

| File | Template | Description |
|---|---|---|
| `patches/YYYY-MM-DD.md` | `patch.md.j2` | Daily report, one section per advisory |
| `README.md` | `readme.md.j2` | Stats header and 10 most recent advisories |
| `docs/index.html` | `index.html.j2` | Full searchable frontend |
| `docs/search-index.json` | Inline | Flat JSON array for client-side search |

### GitHub Pages frontend

The `docs/index.html` is a self-contained single-file application. No build step, no framework, no server-side dependencies.

Features:

- Card grid displaying all advisories with severity badges, language tags, ecosystem labels, and pattern IDs
- Fix quality indicators giving distinct visual treatment to `PARTIAL` and `INCOMPLETE` fixes
- Pattern correlation linking advisories that share a pattern ID
- Client-side full-text search over `docs/search-index.json` covering package names, pattern IDs, root cause text, and fix summaries
- Chart.js dashboard showing severity distribution, top 10 pattern IDs, and language breakdown
- Silent patch section listing commits flagged `SUSPECTED_SILENT_FIX` with confidence levels
- Dark theme using CSS custom properties throughout


## Deployment

### Prerequisites

- A GitHub account with Actions and Pages enabled
- A Gemini API key from [Google AI Studio](https://aistudio.google.com) (free tier is sufficient)

### Step-by-step setup

**1. Fork or clone the repository**

```bash
git clone https://github.com/christbowel/OSDC.git
cd OSDC
```

**2. Add the Gemini API key as a GitHub secret**

Go to: Repository settings > Secrets and variables > Actions > New repository secret

Name: `GEMINI_API_KEY`, value: your key from Google AI Studio.

**3. Enable GitHub Pages**

Go to: Repository settings > Pages > Source: Deploy from a branch > Branch: `main` > Folder: `/docs`

**4. Verify GitHub Actions are enabled**

On a fork, Actions may be disabled by default. Go to the Actions tab and enable them.

**5. (Optional) Backfill historical data**

```bash
pip install -r requirements.txt
export GEMINI_API_KEY=your_key
python -m src.backfill --start 2026-03-01 --end 2026-04-15
```

**6. Trigger the first run**

Go to Actions > Daily Analysis > Run workflow. Or wait for the 06:00 UTC cron.

### Environment variables

| Variable | Required | Default | Description |
|---|---|---|---|
| `GEMINI_API_KEY` | Yes | none | Gemini API authentication |
| `OLLAMA_BASE_URL` | No | `http://localhost:11434` | Ollama fallback endpoint |
| `OSDC_MAX_PER_RUN` | No | `50` | Advisory cap per run |
| `OSDC_DRY_RUN` | No | `false` | Analyze without writing to JSONL |


## Running locally

### Single run

```bash
export GEMINI_API_KEY=your_key
export RUN_NUMBER=1
python -m src.main
```

### Dry run (no writes)

```bash
export GEMINI_API_KEY=your_key
export OSDC_DRY_RUN=true
python -m src.main
```

### Force re-render without re-analysis

```bash
python -c "
from src.db import rebuild_from_jsonl
from src.render import render_all
from datetime import date
rebuild_from_jsonl()
render_all(date.today().isoformat())
"
```

### Rebuild SQLite from JSONL

```bash
python -c "from src.db import rebuild_from_jsonl; rebuild_from_jsonl()"
```

### Inspect current statistics

```bash
python -c "
from src.db import rebuild_from_jsonl, get_stats
import json
rebuild_from_jsonl()
print(json.dumps(get_stats(), indent=2))
"
```

### Reset state cursor manually

Use this to reprocess a date range or recover from a corrupted state file.

```bash
python -c "
import json
from pathlib import Path
Path('data/state.json').write_text(json.dumps({
    'last_run_at': '2026-04-01T00:00:00Z',
    'pending_ids': [],
    'today_advisory_count': 0,
    'today_run_number': 0
}, indent=2))
"
```


## Configuration reference

All values are defined in `src/config.py`.

### LLM parameters

```python
GEMINI_MODEL = "gemini-2.5-flash"
GEMINI_THINKING_BUDGET = 0
GEMINI_MAX_OUTPUT_TOKENS = 8192
OLLAMA_MODEL = "qwen2.5-coder:7b"
OLLAMA_BASE_URL = "http://localhost:11434"
```

### Pipeline parameters

```python
CHECKPOINT_INTERVAL = 5
MAX_DIFF_LINES = 500
MAX_ADVISORIES_PER_RUN = 50
GEMINI_RETRY_ATTEMPTS = 3
GEMINI_RETRY_BACKOFF = [2, 4, 8]
```

### File paths

```python
TAXONOMY_PATH = Path("data/taxonomy.json")
JSONL_PATH = Path("data/patterns.jsonl")
STATE_PATH = Path("data/state.json")
PATCHES_DIR = Path("patches")
DOCS_DIR = Path("docs")
TEMPLATES_DIR = Path("templates")
```

### Diff filtering

```python
EXCLUDED_EXTENSIONS = [
    ".md", ".rst", ".txt", ".lock", ".sum",
    ".png", ".jpg", ".gif", ".svg", ".ico",
    "package-lock.json", "yarn.lock", "Cargo.lock",
    "poetry.lock", "go.sum", "Gemfile.lock",
    # full list in config.py
]

SECURITY_KEYWORDS = [
    "auth", "authz", "authn", "crypto", "encrypt",
    "sanitize", "validate", "permission", "token",
    "session", "cors", "csrf", "xss", "sql",
    "injection", "escape", "hash", "secret", "key",
    # full list in config.py
]
```


## Extending OSDC

### Adding a new LLM provider

Add a function in `analyze.py`:

```python
def _call_myprovider(prompt: str) -> dict | None:
    # call the provider
    # return parsed dict or None on failure
    pass
```

Add it to the fallback chain in `analyze_advisory()`:

```python
result = _call_gemini(prompt) or _call_myprovider(prompt) or _call_ollama(prompt)
```

### Adding a new taxonomy pattern

Edit `data/taxonomy.json`:

```json
{
  "TEMPLATE_INJECTION -> RCE": "Server-side template injection leading to arbitrary code execution",
  "LOG_INJECTION -> SPOOFING": "Unsanitized input written to logs enabling log record forgery"
}
```

The LLM uses new patterns from the next run. No code changes required. Historical `UNCLASSIFIED` records can be reclassified by running `backfill.py` over the existing date range.

### Adding a new analysis field

1. Add the field to the JSON response specification in the prompt inside `analyze.py`
2. Add a `NOT NULL DEFAULT ''` column to the `CREATE TABLE` statement in `db.py`
3. Add the field to the relevant Jinja2 templates
4. Run `rebuild_from_jsonl()` to apply the schema change: historical records carry the default value for the new field

### Adding a new output format

1. Create a Jinja2 template in `templates/`
2. Add a render call in `render.py::render_all()`
3. Add the output path to the `git add` step in `daily.yml`


## Known limitations

**`UNCLASSIFIED` rate with Ollama fallback.** `qwen2.5-coder:7b` has weaker taxonomy adherence than Gemini. Runs that exhaust Gemini quota and fall back to Ollama will produce a higher proportion of `UNCLASSIFIED` records. These can be reprocessed once quota resets by running `backfill.py` with `--reprocess-unclassified`.

**`key_diff` formatting from Qwen.** Qwen occasionally returns `key_diff` as a JSON object `{"before": "...", "after": "..."}` instead of a diff string. `_clean_diff()` normalizes this for display, but the raw JSONL contains the malformed value. This is cosmetic and does not affect pattern correlation.

**GHSA coverage gaps.** GHSA does not cover all CVEs in the NVD. Coverage is strong for npm, PyPI, and Go but weaker for C/C++ projects, firmware, and proprietary ecosystems. Advisories without a fix commit are skipped entirely.

**Silent patch detection threshold.** The silent patch workflow is designed to be enabled after 500 analyzed advisories. Enabling it earlier produces a higher false positive rate because taxonomy classification is not yet well-calibrated. The threshold is enforced as a configuration check in `config.py`.

**No cross-commit deduplication.** A commit that fixes multiple vulnerabilities will generate multiple advisory records pointing to the same diff. The analysis output will be functionally identical across those records. This is visually redundant but does not corrupt the database or statistics.

**GitHub API rate limits.** OSDC requires a `GITHUB_TOKEN` (auto-provided by Actions) which provides 5,000 requests per hour. Running locally without a token will exhaust the unauthenticated limit (60 requests per hour) after roughly 30 advisories.
